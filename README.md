# 🛡️ BeaconGuardian - 데이터 수집 에이전트

Beacon 보안 모니터링 시스템을 위한 데이터 수집 에이전트

## 📋 개요

BeaconGuardian은 시스템 활동을 실시간으로 모니터링하고 Beacon 서버로 데이터를 전송하는 에이전트입니다.

## ✨ 주요 기능

### 🔍 모니터링 기능

| 모듈 | 기능 | 설명 |
|------|------|------|
| 🔌 **USB 모니터** | USB 장치 감지 | 연결/제거 이벤트 실시간 추적 |
| 🖥️ **프로세스 모니터** | 프로세스 추적 | 실행/종료/의심 프로세스 탐지 |
| 📂 **파일 감시** | 파일 시스템 | 중요 디렉토리 변경 감지 |
| 🌍 **브라우저 모니터** | 웹 히스토리 | Chrome/Edge/Firefox 방문 기록 ⭐ NEW |

### 🎯 브라우저 모니터링 (NEW!)

**실제 방문한 URL을 추적합니다:**
```
✅ 완전한 URL (https://www.google.com/search?q=test)
✅ 페이지 제목
✅ 방문 횟수
✅ 방문 시간
✅ 브라우저 종류 (Chrome, Edge, Firefox)
```

**지원 브라우저:**
- ✅ Google Chrome
- ✅ Microsoft Edge
- ✅ Mozilla Firefox

**전송 데이터 예시:**
```json
{
  "eventType": "WEB_VISIT",
  "severity": "low",
  "description": "Chrome 웹 방문: https://www.google.com",
  "metadata": {
    "browser": "Chrome",
    "url": "https://www.google.com",
    "title": "Google",
    "visit_count": 5,
    "timestamp": 1710123456.789
  }
}
```

## 🚀 설치 및 실행

### 1. 요구사항

```
✅ Python 3.8+
✅ Windows 10/11 또는 Linux
✅ Beacon 서버 실행 중
```

### 2. 설치

```bash
cd BeaconGuardian

# 가상환경 생성
python -m venv .venv

# 가상환경 활성화
# Windows:
.venv\Scripts\activate
# Linux:
source .venv/bin/activate

# 의존성 설치
pip install -r requirements.txt
```

### 3. 설정

`config.yaml` 파일 수정:

```yaml
beacon:
  server_url: "http://localhost:8080"  # Beacon 서버 URL
  username: "admin"                     # 사용자명
  password: "admin1234"                 # 비밀번호

monitoring:
  usb_check_interval: 5        # USB 체크 간격 (초)
  network_check_interval: 10   # 네트워크 체크 간격
  process_check_interval: 5    # 프로세스 체크 간격
  browser_check_interval: 30   # 브라우저 히스토리 체크 간격

paths:
  watch_dirs:
    - "C:\\Windows\\System32"
    - "C:\\Users\\User\\Documents"

logging:
  level: "INFO"
  file: "agent.log"
```

### 4. 실행

**일반 실행:**
```bash
python agent.py
```

**관리자 권한으로 실행 (네트워크 캡처용):**
```bash
# Windows: PowerShell을 관리자 권한으로 실행 후
python agent.py

# Linux:
sudo python agent.py
```

## 📊 모니터링 데이터

### USB 이벤트
```json
{
  "eventType": "USB_CONNECTED",
  "severity": "medium",
  "description": "USB 장치 연결: E:\\",
  "metadata": {
    "device": "E:",
    "mountpoint": "E:\\",
    "fstype": "FAT32"
  }
}
```

### 네트워크 트래픽 (삭제 예정)
```json
{
  "sourceIp": "192.168.1.50",
  "destinationIp": "172.217.161.78",
  "protocol": "TCP",
  "destinationPort": 443,
  "bytesTransferred": 102400,
  "packetsTransferred": 150
}
```

### 프로세스 이벤트
```json
{
  "eventType": "PROCESS_START",
  "severity": "low",
  "description": "Process started: chrome.exe",
  "metadata": {
    "pid": 1234,
    "name": "chrome.exe",
    "exe": "C:\\Program Files\\Google\\Chrome\\chrome.exe"
  }
}
```

### 웹 방문 기록 🌍
```json
{
  "eventType": "WEB_VISIT",
  "severity": "low",
  "description": "Chrome 웹 방문: https://www.naver.com",
  "metadata": {
    "browser": "Chrome",
    "url": "https://www.naver.com",
    "title": "NAVER",
    "visit_count": 3,
    "timestamp": 1710123456.789
  }
}
```

## ⚙️ Windows 서비스 설치

### 자동 설치

```bash
# 관리자 권한으로 실행
install_service.bat
```

### 수동 설치 (NSSM 사용)

```bash
# NSSM 다운로드
https://nssm.cc/download

# 서비스 설치
nssm install BeaconGuardian "C:\Python\python.exe" "C:\Path\To\agent.py"

# 서비스 시작
nssm start BeaconGuardian
```

## 🐧 Linux Systemd 서비스

### 서비스 파일 생성

```bash
sudo nano /etc/systemd/system/beacon-guardian.service
```

```ini
[Unit]
Description=BeaconGuardian Security Monitoring Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/BeaconGuardian
ExecStart=/opt/BeaconGuardian/.venv/bin/python agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 서비스 등록 및 시작

```bash
sudo systemctl daemon-reload
sudo systemctl enable beacon-guardian
sudo systemctl start beacon-guardian
sudo systemctl status beacon-guardian
```

## 🔧 문제 해결

### 네트워크 캡처 오류

**문제:**
```
Error: winpcap is not installed
```

**해결:**
1. Npcap 설치: https://npcap.com
2. 관리자 권한으로 실행

### 서버 연결 실패

**문제:**
```
Connection to localhost:8080 timed out
```

**해결:**
1. Beacon 서버가 실행 중인지 확인
2. config.yaml의 server_url 확인
3. 방화벽 설정 확인

### 브라우저 히스토리 접근 불가

**문제:**
```
Error reading Chrome history: database is locked
```

**해결:**
- 정상 동작입니다. 에이전트가 자동으로 임시 복사본을 사용합니다.
- 브라우저가 실행 중이어도 히스토리를 안전하게 읽습니다.

## 📝 로그

로그는 `agent.log` 파일에 기록됩니다:

```
2026-03-12 02:20:09 [INFO] SecurityAgent: Security Agent starting...
2026-03-12 02:20:19 [INFO] USBMonitor: USB Monitor thread started.
2026-03-12 02:20:19 [INFO] BrowserMonitor: Browser Monitor thread started.
2026-03-12 02:20:49 [INFO] BrowserMonitor: Found 15 new web visits
```

## 📦 의존성

```
psutil        # 시스템 정보
scapy         # 네트워크 패킷 캡처
watchdog      # 파일 시스템 감시
requests      # HTTP 통신
pyyaml        # 설정 파일
```

## 🤝 Beacon 서버 연동

BeaconGuardian은 다음 API 엔드포인트로 데이터를 전송합니다:

- `POST /api/auth/login` - 인증
- `POST /api/security-events` - 보안 이벤트
- `POST /api/traffic` - 네트워크 트래픽

## 📊 성능

| 항목 | 값 |
|------|-----|
| CPU 사용률 | < 5% |
| 메모리 사용 | ~50MB |
| 네트워크 | 최소 (이벤트 발생 시만) |
| 디스크 I/O | 최소 |

## 🔐 보안

- ✅ JWT 토큰 기반 인증
- ✅ HTTPS 통신 지원
- ✅ 민감 정보 로컬 저장 안 함
- ✅ 브라우저 히스토리 안전하게 읽기

## 📄 라이선스

MIT License

## 👨‍💻 개발자

- BeaconGuardian Agent
- Part of Beacon Security Monitoring System

---

**🌟 Beacon 서버와 함께 사용하여 완벽한 보안 모니터링을 구현하세요!**
