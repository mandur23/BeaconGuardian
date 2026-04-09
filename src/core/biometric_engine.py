import os
import time
import json
import logging
import threading
import numpy as np
import joblib
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class BiometricLSTM(nn.Module):
    def __init__(self, num_dim, seq_len, hidden_dim=64):
        super(BiometricLSTM, self).__init__()
        self.seq_len = seq_len
        self.encoder = nn.LSTM(num_dim, hidden_dim, batch_first=True, num_layers=2)
        self.decoder = nn.LSTM(hidden_dim, num_dim, batch_first=True, num_layers=2)
        self.regressor = nn.Linear(num_dim, num_dim)

    def forward(self, x):
        _, (h, _) = self.encoder(x)
        h_last = h[-1].unsqueeze(1).repeat(1, self.seq_len, 1)
        reconstructed, _ = self.decoder(h_last)
        return self.regressor(reconstructed)

class BiometricEngine:
    """
    에이전트별 맞춤형 마우스 생체 인증 엔진
    - 상태: COLLECTING -> TRAINING -> GUARDING
    """
    def __init__(self, model_dir, target_samples=2000, seq_len=20):
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)
        self.logger = logging.getLogger("BiometricEngine")
        
        self.target_samples = target_samples
        self.seq_len = seq_len
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # 상태 변수
        self.mode = "COLLECTING"  # COLLECTING, TRAINING, GUARDING
        self.progress = 0.0       # 0.0 ~ 100.0
        self.sample_count = 0
        
        # 데이터 버퍼
        self.training_buffer = []  # 학습용 (N개 모으면 학습 시작)
        self.inference_buffer = [] # 실시간 추론용 (최근 20개 유지)
        
        # 모델 및 전처리기
        self.model = None
        self.if_model = None
        self.scaler = StandardScaler()
        self.lstm_threshold = 0.0
        self.if_threshold = 0.0
        
        # 락
        self.lock = threading.Lock()
        
        # 초기화 시 기존 모델 확인
        self._load_local_model()

    def _get_model_paths(self):
        return (
            os.path.join(self.model_dir, "model.pth"),
            os.path.join(self.model_dir, "scaler.pkl"),
            os.path.join(self.model_dir, "iforest.pkl"),
            os.path.join(self.model_dir, "meta.json")
        )

    def _load_local_model(self):
        m_path, s_path, i_path, meta_path = self._get_model_paths()
        if all(os.path.exists(p) for p in [m_path, s_path, i_path, meta_path]):
            try:
                self.scaler = joblib.load(s_path)
                self.if_model = joblib.load(i_path)
                
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                    self.lstm_threshold = meta.get("lstm_threshold", 0.0123)
                    self.if_threshold = meta.get("if_threshold", 0.0)
                
                num_features = self.scaler.n_features_in_
                self.model = BiometricLSTM(num_features, self.seq_len).to(self.device)
                self.model.load_state_dict(torch.load(m_path, map_location=self.device, weights_only=False))
                self.model.eval()
                
                self.mode = "GUARDING"
                self.progress = 100.0
                self.logger.info("기존 사용자 모델 로드 완료. 감시 모드 시작.")
            except Exception as e:
                self.logger.error("기존 모델 로드 실패: %s", e)
                self.mode = "COLLECTING"

    def feed_data(self, features):
        """실시간 마우스 피처를 엔진에 공급"""
        with self.lock:
            if self.mode == "COLLECTING":
                self.training_buffer.append(features)
                self.sample_count = len(self.training_buffer)
                self.progress = min(99.0, (self.sample_count / self.target_samples) * 100.0)
                
                if self.sample_count >= self.target_samples:
                    self.mode = "TRAINING"
                    thread = threading.Thread(target=self._start_training)
                    thread.daemon = True
                    thread.start()
                    
            elif self.mode == "GUARDING":
                self.inference_buffer.append(features)
                if len(self.inference_buffer) > self.seq_len:
                    self.inference_buffer.pop(0)

    def _start_training(self):
        self.logger.info("학습 데이터 수집 완료. 학습을 시작합니다...")
        try:
            data = np.array(self.training_buffer)
            # 1. 스케일링
            X_scaled = self.scaler.fit_transform(data)
            
            # 2. Isolation Forest 학습 (최근 데이터 포인트 대상)
            # if_features: dist, speed, accel, ang_change, jerk, curvature (기존 suzip 로직 기반)
            # 여기서는 전체 피처 사용
            self.if_model = IsolationForest(n_estimators=200, contamination=0.03, random_state=42)
            self.if_model.fit(X_scaled)
            if_scores = self.if_model.decision_function(X_scaled)
            self.if_threshold = float(np.percentile(if_scores, 1.0)) # 하위 1%
            
            # 3. LSTM AE 학습
            num_features = X_scaled.shape[1]
            # 시퀀스 생성
            seqs = []
            for i in range(len(X_scaled) - self.seq_len + 1):
                seqs.append(X_scaled[i : i + self.seq_len])
            X_seq = torch.FloatTensor(np.array(seqs)).to(self.device)
            
            model = BiometricLSTM(num_features, self.seq_len).to(self.device)
            optimizer = optim.Adam(model.parameters(), lr=1e-3)
            criterion = nn.MSELoss()
            
            model.train()
            for epoch in range(20):
                optimizer.zero_grad()
                output = model(X_seq)
                loss = criterion(output, X_seq)
                loss.backward()
                optimizer.step()
                if epoch % 5 == 0:
                    self.logger.info(f"학습 중... Epoch {epoch}/20, Loss: {loss.item():.6f}")
            
            # 4. 임계치 계산 (MSE 99백분위수)
            model.eval()
            with torch.no_grad():
                recon = model(X_seq)
                mses = torch.mean((X_seq - recon)**2, dim=(1,2)).cpu().numpy()
                self.lstm_threshold = float(np.percentile(mses, 99.0))
            
            self.model = model
            self._save_model()
            
            with self.lock:
                self.mode = "GUARDING"
                self.progress = 100.0
                self.training_buffer = [] # 메모리 해제
            self.logger.info("학습 종료 및 감시 모드 전환 완료.")
            
        except Exception as e:
            self.logger.error("학습 도중 오류 발생: %s", e)
            self.mode = "COLLECTING"
            self.progress = 0.0

    def _save_model(self):
        m_path, s_path, i_path, meta_path = self._get_model_paths()
        torch.save(self.model.state_dict(), m_path)
        joblib.dump(self.scaler, s_path)
        joblib.dump(self.if_model, i_path)
        meta = {
            "lstm_threshold": self.lstm_threshold,
            "if_threshold": self.if_threshold,
            "trained_at": time.time(),
            "samples": self.target_samples
        }
        with open(meta_path, 'w') as f:
            json.dump(meta, f)

    def analyze(self):
        """현재 버퍼를 기준으로 이상 징후 분석"""
        with self.lock:
            if self.mode != "GUARDING" or len(self.inference_buffer) < self.seq_len:
                return None
            
            input_seq = np.array(self.inference_buffer)
            X_scaled = self.scaler.transform(input_seq)
            
            # LSTM MSE
            input_tensor = torch.FloatTensor(X_scaled).unsqueeze(0).to(self.device)
            with torch.no_grad():
                output = self.model(input_tensor)
                mse = torch.mean((output - input_tensor)**2).item()
            
            # iForest Score (가장 최근 포인트)
            if_score = float(self.if_model.decision_function([X_scaled[-1]])[0])
            
            is_anomaly = (mse > self.lstm_threshold * 1.5) or (if_score < self.if_threshold)
            risk_score = min(10.0, (mse / self.lstm_threshold) * 5.0)
            
            return {
                "is_anomaly": is_anomaly,
                "risk_score": risk_score,
                "mse": mse,
                "if_score": if_score,
                "thresholds": {"lstm": self.lstm_threshold, "if": self.if_threshold}
            }

    def reset_model(self):
        """모델 초기화 및 재학습 모드 전환"""
        with self.lock:
            self.mode = "COLLECTING"
            self.progress = 0.0
            self.sample_count = 0
            self.training_buffer = []
            self.model = None
            # 물리적 파일 삭제
            for p in self._get_model_paths():
                if os.path.exists(p):
                    os.remove(p)
        self.logger.info("모델 초기화 완료. 새 학습을 시작합니다.")
