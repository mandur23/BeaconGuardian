import json
import logging
import os
import threading
import time
import queue
import numpy as np
try:
    import torch
    from pynput import mouse
    from core.biometric_engine import BiometricEngine
    HAS_AI_LIBS = True
except ImportError:
    HAS_AI_LIBS = False

class InputBiometricMonitor(threading.Thread):
    """
    고급 개인별 맞춤형 마우스 생체 인증 모니터 (비동기 최적화 버전)
    - 마우스 렉 현상을 방지하기 위해 큐(Queue) 기반 비동기 처리 도입
    """

    def __init__(self, output_path, callback=None, model_dir=None, target_samples=2000, auto_block=False):
        super().__init__()
        self.output_path = output_path
        self.callback = callback
        self.logger = logging.getLogger("InputBiometricMonitor")
        self.daemon = True
        self.running = True
        self.auto_block = auto_block
        self.event_queue = queue.Queue()

        # 엔진 초기화
        default_model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "biometric")
        m_dir = model_dir or default_model_dir
        
        if HAS_AI_LIBS:
            self.engine = BiometricEngine(model_dir=m_dir, target_samples=target_samples)
        else:
            self.engine = None
            self.logger.error("AI 라이브러리(torch 등)가 없어 생체 인증 엔진을 시작할 수 없습니다.")

        # 상태 추적용 변수 (워커 스레드에서만 접근)
        self.last_pos = None
        self.last_time = time.time()
        self.prev_vector = (0.0, 0.0)
        self.last_accel = 0.0
        self.is_dragging = False

        # 로컬 로깅용
        self._events_to_flush = []
        self._flush_lock = threading.Lock()

    def calculate_ang_change(self, dx, dy, dist):
        curr_vector = (dx, dy)
        mag_prev = np.sqrt(self.prev_vector[0]**2 + self.prev_vector[1]**2)
        if dist < 1e-7 or mag_prev < 1e-7:
            self.prev_vector = curr_vector
            return 0.0
        dot = dx * self.prev_vector[0] + dy * self.prev_vector[1]
        cos_theta = max(-1.0, min(1.0, dot / (dist * mag_prev + 1e-9)))
        angle = np.arccos(cos_theta)
        self.prev_vector = curr_vector
        return angle

    # --- Listener Callbacks (최소한의 작업만 수행) ---
    def on_move(self, x, y):
        if self.running:
            self.event_queue.put(("MOVE", x, y, time.time()))

    def on_click(self, x, y, button, pressed):
        if self.running:
            self.event_queue.put(("CLICK", x, y, button, pressed, time.time()))

    def on_scroll(self, x, y, dx, dy):
        if self.running:
            self.event_queue.put(("SCROLL", x, y, dx, dy, time.time()))

    # --- Worker Logic ---
    def _process_worker(self):
        """별도 스레드에서 큐에 쌓인 이벤트를 처리하여 시스템 지연을 방지"""
        self.logger.info("Biometric processing worker started.")
        while self.running:
            try:
                # 큐가 빌 때까지 기다림 (타임아웃을 주어 종료 체크 가능하게 함)
                item = self.event_queue.get(timeout=0.1)
                etype = item[0]

                if etype == "MOVE":
                    _, x, y, curr_t = item
                    self._handle_move(x, y, curr_t)
                elif etype == "CLICK":
                    _, x, y, button, pressed, curr_t = item
                    self.is_dragging = pressed
                    self._append_local_event("MOUSE_CLICK", {"x": x, "y": y, "button": str(button), "pressed": bool(pressed)}, curr_t)
                elif etype == "SCROLL":
                    _, x, y, dx, dy, curr_t = item
                    self._append_local_event("MOUSE_SCROLL", {"x": x, "y": y, "dx": dx, "dy": dy}, curr_t)
                
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in biometric worker: {e}")

    def _handle_move(self, x, y, curr_t):
        if self.last_pos is None:
            self.last_pos = (x, y)
            self.last_time = curr_t
            return

        dt = curr_t - self.last_time
        if dt >= 0.05: # 20Hz Sampling (입력 훅 밖에서 연동되므로 렉 유발 없음)
            dx, dy = x - self.last_pos[0], y - self.last_pos[1]
            dist = np.sqrt(dx**2 + dy**2)
            ang_change = self.calculate_ang_change(dx, dy, dist)
            speed = dist / dt
            accel = speed / dt
            jerk = (accel - self.last_accel) / dt
            curvature = ang_change / (dist + 1e-7)
            self.last_accel = accel

            if self.engine:
                features = [dx, dy, dist, speed, accel, ang_change, dt, jerk, curvature]
                self.engine.feed_data(features)

            self._append_local_event("MOUSE_MOVE", {"x": x, "y": y, "speed": speed, "accel": accel, "is_dragging": self.is_dragging}, curr_t)
            self.last_pos, self.last_time = (x, y), curr_t

    def _append_local_event(self, event_type, data, timestamp):
        event = {"eventType": event_type, "timestamp": timestamp, "data": data}
        if self.engine:
            event["engine_mode"] = self.engine.mode
            event["progress"] = self.engine.progress
            
        with self._flush_lock:
            self._events_to_flush.append(event)

    def run(self):
        if not HAS_AI_LIBS:
            return

        # 리스너 시작
        listener = mouse.Listener(on_move=self.on_move, on_click=self.on_click, on_scroll=self.on_scroll)
        listener.start()

        # 워커 스레드 시작
        worker = threading.Thread(target=self._process_worker, daemon=True)
        worker.start()

        self.logger.info("Asynchronous Adaptive Biometric Monitor started.")
        while self.running:
            time.sleep(1.0)
            self._flush_local_events()
            
            if self.engine and self.engine.mode == "GUARDING":
                analysis = self.engine.analyze()
                if analysis and analysis["is_anomaly"]:
                    self._report_anomaly(analysis)

        listener.stop()

    def _report_anomaly(self, analysis):
        if not self.callback:
            return
        
        risk = analysis["risk_score"]
        mse = analysis["mse"]
        if_score = analysis["if_score"]
        
        event = {
            "eventType": "BIOMETRIC_ANOMALY",
            "severity": "HIGH" if risk > 7.0 else "MEDIUM",
            "summary": "침입자 의심: 사용자 마우스 행동 패턴 불일치",
            "description": f"신뢰도 위반 탐지 (MSE: {mse:.5f}, iF: {if_score:.4f})",
            "riskScore": risk,
            "metadata": {
                "mse": mse, 
                "if_score": if_score,
                "auto_block": self.auto_block
            }
        }
        self.callback(event)
        
        if self.auto_block and risk > 8.5:
            self.logger.critical("Critical Anomaly! Triggering Automatic Local Block.")
            try:
                from firewall.local_block_controller import LocalBlockController
                lbc = LocalBlockController()
                lbc.block_network(reason=f"Biometric anomaly (MSE:{mse:.4f})")
            except Exception as e:
                self.logger.error("Auto-block failed: %s", e)

    def _flush_local_events(self):
        with self._flush_lock:
            if not self._events_to_flush:
                return
            batch = self._events_to_flush
            self._events_to_flush = []

        try:
            os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
            with open(self.output_path, "a", encoding="utf-8") as f:
                for row in batch:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.error("Failed to write local bio logs: %s", e)

    def stop(self):
        self.running = False
