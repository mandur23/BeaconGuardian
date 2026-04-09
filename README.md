# BeaconGuardian — 데이터 수집 에이전트

Beacon 보안 모니터링 시스템용 엔드포인트 에이전트입니다. USB·프로세스·파일·네트워크·브라우저 활동을 수집해 Beacon 서버로 전송합니다.

## 개요

BeaconGuardian은 시스템 활동을 주기적으로 모니터링하고, 설정에 따라 Beacon 서버로 이벤트·트래픽 데이터를 보냅니다. 일부 수집(입력 생체)은 **로컬 파일만** 기록하며 서버로 보내지 않습니다.

## 주요 기능

### 모니터링 모듈

| 모듈 | 기능 | 설명 |
|------|------|------|
| **USB** | USB 장치 | 연결/제거 이벤트 |
| **프로세스** | 프로세스 | 실행·종료 등 |
| **파일 감시** | 파일 시스템 | 지정 디렉터리 변경 감지 |
| **네트워크** | 로컬 트래픽 | 패킷 기반 트래픽 요약(관리자/Npcap 권장) |
| **브라우저** | 웹 히스토리 | Chrome / Edge / Firefox 방문 기록 |
| **입력 생체** | 키보드·마우스 | 카테고리·좌표 등 **로컬 JSONL만** 저장, 서버 미전송 |

### 브라우저 모니터링

- 방문 URL, 페이지 제목, 방문 횟수, 타임스탬프, 브라우저 종류

**전송 이벤트 예시:**

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

## 설정 UI · 관리자 / 일반 사용자

로그인(`POST /api/auth/login`) 성공 후 역할(`admin` / `user`)에 따라 **창·트레이·종료 가능 여부**만 달라지고, 에이전트 수집·전송 로직은 동일합니다.

| 구분 | 창 | 종료(헤더 **종료**·X) | 트레이 |
|------|-----|----------------------|--------|
| **관리자** | 설정 마법사 표시 | 확인 후 앱 종료 | (선택) |
| **일반** | 기존 `config.yaml`이 있으면 자동으로 숨김 | X는 창만 숨기고 트레이로 복귀(프로세스 유지) | 아이콘 + **창 열기**만(종료 메뉴 없음) |

- 역할은 **서버 응답 JSON**의 `role` / `userRole` 우선, 없으면 **`config.yaml`의 `ui.admin_usernames`**(Windows 로그온 사용자명)에 포함되면 관리자로 간주합니다.
- `config.yaml`이 없어 최초 설정이 필요한 일반 사용자는 마법사를 마칠 때까지 창이 표시됩니다.
- 로그인 창의 **「유저 로그인 · 백그라운드로 시작」**은 서버 로그인 없이, **관리자가 이미 저장한 `config.yaml`**만으로 에이전트를 띄우고 트레이로 넘깁니다(`config`가 없거나 서버 URL·사용자명이 비어 있으면 사용할 수 없음).
- 개발용으로 `ui.skip_login: true`이면 로그인 창을 건너뛰며, 역할은 `ui.default_role`(기본 `admin`)을 따릅니다.
- 일반 사용자는 UI에서 앱을 완전히 종료하지 못합니다. 업데이트·재시작은 관리자 계정·설치 프로그램·작업 관리자 등으로 처리하는 시나리오를 권장합니다.

## 설치 및 실행

### 요구사항

- Python 3.8+
- Windows 10/11 또는 Linux
- Beacon 서버(백엔드) 동작 중
- 네트워크 패킷 수집(Windows): [Npcap](https://npcap.com) + 관리자 권한 권장

### 설치

```bash
cd BeaconGuardian

python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

**선택:** 입력 생체 모듈을 쓰려면 `pynput`을 추가로 설치합니다. 미설치 시 해당 수집은 비활성화됩니다.

```bash
pip install pynput
```

### 설정

프로젝트 루트에 `config.yaml`을 두고 값을 맞춥니다. (저장소에 샘플이 없으면 아래를 참고해 새로 만듭니다.)

```yaml
beacon:
  server_url: "http://localhost:8080"
  username: "admin"
  password: "admin1234"
  ip_selection: "outbound"
  jwt_refresh_before_exp_seconds: 90
  # tls:
  #   require_https: true
  #   ca_bundle: "C:\\path\\ca.pem"
  #   client_cert: "C:\\path\\client.crt"
  #   client_key: "C:\\path\\client.key"
  #   pin_spki_sha256: ["<SPKI SHA256 hex>"]

agent:
  agent_name: "DESKTOP-USER01"
  agent_version: "1.0.0"
  heartbeat_interval_seconds: 10

collectors:
  usb: true
  network: true
  process: true
  filesystem: true
  browser_history: true
  input_biometric: true   # 로컬 파일만; 서버 전송 없음

monitoring:
  usb_check_interval: 5
  network_check_interval: 10
  process_check_interval: 5
  browser_check_interval: 30
  biometric_flush_interval: 2
  mouse_move_sample_ms: 120

paths:
  watch_dirs:
    - "C:\\Windows\\System32"
    - "C:\\Users\\User\\Documents"
  biometric_log_file: "logs/biometric_input.jsonl"

logging:
  level: "INFO"
  file: "logs/agent.log"
  max_bytes: 10485760
  backup_count: 5

ui:
  dark_mode: false
  skip_login: false
  default_role: admin
  admin_usernames: []
```

첫 실행 시 `beacon.password`가 평문이면 자동으로 암호화되어 `config.yaml`에 다시 저장됩니다(`cryptography` 사용).

### 실행

**기본:** 인자 없이 실행하면 **설정 마법사(GUI)만** 열리고, 같은 프로세스에서 모니터가 바로 돌지 않습니다. 마법사에서 저장·시작을 완료하면 **`--no-ui` 자식 프로세스**로 에이전트가 뜹니다. 헤드리스/서비스로만 쓸 때는 처음부터 `--no-ui`를 쓰면 됩니다.

**기본 (GUI 먼저):**

```bash
python src/agent.py
```

**UI 없이 바로 에이전트만 실행:**

```bash
python src/agent.py --no-ui
```

**설정 파일 경로 지정:**

```bash
python src/agent.py --no-ui --config C:\path\to\config.yaml
```

네트워크 캡처가 필요하면 Windows에서는 PowerShell을 **관리자 권한**으로 연 뒤 위와 같이 실행합니다.

### 개발: 테스트

```bash
pip install pytest
set PYTHONPATH=src   # Windows PowerShell: $env:PYTHONPATH = "src"
pytest tests
```

`BeaconClient` 정규화·방화벽 revision 판단 등 순수 로직은 `tests/` 에서 검증합니다.

### Windows exe 빌드 (콘솔 숨김)

PyInstaller로 묶을 때 **`--noconsole`**(또는 `-w` / `--windowed`)을 쓰면 실행 시 **검은 콘솔 창이 뜨지 않습니다.**

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name BeaconGuardian src/agent.py
```

산출물은 `dist/BeaconGuardian.exe`입니다. 설정 UI가 `에이전트 시작`으로 자식 프로세스를 띄울 때도 **콘솔 창을 만들지 않도록** `CREATE_NO_WINDOW` 플래그를 사용합니다(Windows).

## 모니터링 데이터 예시

### USB

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

### 네트워크 트래픽

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

### 프로세스

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

### 웹 방문

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

## Windows 서비스 (NSSM 예시)

```text
nssm install BeaconGuardian "C:\Path\To\.venv\Scripts\python.exe" "C:\Path\To\BeaconGuardian\src\agent.py"
nssm set BeaconGuardian AppParameters --no-ui
nssm start BeaconGuardian
```

`python.exe`와 프로젝트 경로는 본인 환경에 맞게 바꿉니다.

## Linux (systemd) 예시

```ini
[Unit]
Description=BeaconGuardian Security Monitoring Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/BeaconGuardian
ExecStart=/opt/BeaconGuardian/.venv/bin/python src/agent.py --no-ui
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable beacon-guardian
sudo systemctl start beacon-guardian
sudo systemctl status beacon-guardian
```

## 문제 해결

### 네트워크 캡처 오류 (`winpcap` / Npcap)

1. [Npcap](https://npcap.com) 설치(WinPcap API 호환 옵션 권장)
2. 에이전트를 관리자 권한으로 실행

### 서버 연결 실패

1. Beacon 서버 프로세스·포트 확인
2. `config.yaml`의 `beacon.server_url` 확인
3. 방화벽·프록시 설정 확인

### Chrome 히스토리 `database is locked`

브라우저 사용 중일 때 흔합니다. 에이전트가 임시 복사본으로 읽도록 동작합니다.

## 로그

기본 로그 파일: `logs/agent.log`(프로젝트 루트 기준 상대 경로). 로테이션은 `logging.max_bytes`, `logging.backup_count`로 조절합니다.

## 의존성 (`requirements.txt`)

| 패키지 | 용도 |
|--------|------|
| PyYAML | 설정 |
| requests | HTTP |
| psutil | 시스템·프로세스 |
| scapy | 패킷/트래픽 |
| watchdog | 파일 감시 |
| cryptography | 설정 비밀번호 암호화 |
| pynput | (선택) 입력 생체 수집 |

## Beacon 서버 연동

엔드포인트·JWT·TLS·IP 등록 등 상세 내용은 [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md)를 참고하세요.

- `POST /api/auth/login` — 로그인(JWT)
- `POST /api/agents/register` — 에이전트 등록
- `POST /api/agents/heartbeat` — 하트비트
- `POST /api/agents/disconnect` — 연결 해제(선택)
- `POST /api/security-events` — 보안 이벤트
- `POST /api/traffic` — 네트워크 트래픽

## 보안

- JWT 기반 API 인증
- HTTPS·TLS·인증서 핀닝 설정 가능(`beacon.tls`)
- 입력 생체는 설계상 **서버 미전송**, 로컬 JSONL만 기록

## 라이선스

MIT License

## 개발

Beacon Security Monitoring System의 일부로 유지보수됩니다.
