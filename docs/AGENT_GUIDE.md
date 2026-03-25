# BeaconGuardian 에이전트 가이드

Beacon은 **네트워크 경유 트래픽**과 **각 PC의 호스트 정보**를 서로 다른 경로로 수집합니다.

| 구분 | 역할 | 수집 경로 (이 레포 기준) |
|------|------|---------------------------|
| **Suricata** | 허브 경유 패킷, IDS 알림 등 **네트워크 레벨** 이벤트 | EVE JSON 파일(`eve.json`) tail 또는 Syslog UDP → Spring Boot |
| **BeaconGuardian** | USB·프로세스·파일·로컬 패킷 등 **엔드포인트·호스트** 데이터 | 클라이언트 → HTTPS REST (`/api/agents`, `/api/traffic`, `/api/security-events`) |

이 문서는 **BeaconGuardian** 쪽만 다룹니다. Suricata는 Pi(또는 센서 서버)의 `suricata.eve.*` 설정과 `EveJsonFileWatcherService`를 참고하세요.

---

## 1. 사전 요구사항

- **Windows**: [Npcap](https://npcap.com) 설치(로컬 패킷 수집 시). 설치 시 WinPcap API 호환 모드 권장.
- **Pi(또는 Beacon 서버) 주소**: 예) `http://192.168.0.10:8080`
- 운영 환경에서는 **HTTPS**와 방화벽(포트 8080 등)만 허용 목록으로 제한하는 것을 권장합니다.

---

## 2. 인증 (필수)

Spring Security 설정상 **`/api/auth/**`를 제외한 모든 `/api/*` 요청은 인증이 필요**합니다.  
BeaconGuardian은 **먼저 로그인해 JWT를 받은 뒤**, 이후 모든 API 호출에 **`Authorization: Bearer <token>`** 헤더를 붙여야 합니다.

### 2.1 로그인

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "관리자_계정",
  "password": "비밀번호"
}
```

응답의 `token` 값을 저장해 두고, 아래 모든 요청에 사용합니다.

### 2.2 공통 헤더 예시

```http
Authorization: Bearer <JWT>
Content-Type: application/json
```

### 2.3 전송 계층(TLS)·인증·페이로드 민감도

JSON 자체는 암호화가 아닙니다. **기밀성·무결성**은 주로 **TLS(HTTPS)**가 담당하고, **누가 보냈는지**는 **인증(JWT 등)**이 담당합니다. 페이로드에는 **민감한 호스트 정보**가 들어갈 수 있어 설계·보관 정책이 필요합니다.

#### 전송 계층 (TLS)

- **HTTPS**로만 Beacon 서버와 통신하는 것을 기본으로 합니다. 평문 HTTP는 LAN에서도 스니핑·중간자 공격에 노출됩니다.
- 서버에 **신뢰할 수 있는 인증서**(공인 CA, 또는 사내 PKI)를 적용합니다. 에이전트는 **인증서 검증을 끄지 않는 것**이 안전합니다(개발 전용 예외만 최소화).
- 운영에서는 **TLS 1.2 이상**만 허용, 암호 스위트는 서버 가이드에 맞게 강화합니다.
- 추가로 필요하면 **mTLS(클라이언트 인증서)**로 “이 PC의 에이전트만” 연결을 제한할 수 있습니다(JWT와 병행 가능).

#### 인증 (JWT와의 역할 분리)

- **TLS**: 전송 구간 암호화·서버 신원(및 선택적으로 클라이언트 신원).
- **JWT**: 애플리케이션 레벨에서 **로그인된 사용자(또는 발급 정책에 따른 주체)**임을 증명. 토큰이 유출되면 해당 권한이 노출되므로:
  - 에이전트 프로세스 메모리에 보관하고 **디스크·로그에 평문 저장 금지**
  - 만료 시 재로그인 또는 **짧은 만료 + 갱신** 정책(서버가 지원할 때)
- 로그인 요청 본문의 **비밀번호**는 반드시 **HTTPS** 위에서만 전송합니다.

#### 페이로드 민감도

- `metadata`, `description`, `rawData` 등에 **파일 경로, URL, 사용자명, 장치 식별자** 등이 들어갈 수 있습니다. 수집·전송·DB 저장 범위를 **최소한**으로 정하는 것이 좋습니다.
- TLS로 구간은 보호되어도, **서버 DB·백업·로그**에 남는 데이터는 별도로 보호합니다(접근 통제, 마스킹, 보존 기간).
- 규제/내부 정책이 있으면 **목적에 필요한 필드만** 보내고, 브라우저 기록·USB 상세 등은 **별도 동의·정책** 하에 켜는 방식을 권장합니다.

### 2.4 인증서 고정 (Certificate / Public Key Pinning)

일반 TLS는 OS·브라우저가 신뢰하는 **CA 목록**을 따릅니다. **고정(pinning)**은 BeaconGuardian HTTP 클라이언트가 **우리 서버의 공개키(또는 SPKI 해시)**만 신뢰하도록 제한해, 잘못된 CA가 발급한 위조 인증서나 **기업 프록시가 TLS를 가로채는 경우**를 완화합니다.

- **무엇을 고정할지**
  - **공개키 핀(SPKI hash)**: 인증서가 갱신돼도 **같은 키를 재사용**하면 핀을 바꾸지 않아도 되는 경우가 많아 관리가 쉽습니다.
  - **전체 인증서 핀**: 갱신마다 에이전트 설정을 바꿔야 할 수 있습니다.

- **백업 핀(backup pin)**: 서버 인증서를 교체할 때를 대비해 **차기 공개키**를 미리 하나 더 넣어 두면 다운타임을 줄일 수 있습니다.

- **운영 시 유의**
  - 인증서·키 **롤오버 전**에 에이전트 설정(핀 목록)을 배포하는 절차가 필요합니다.
  - 핀이 서버와 맞지 않으면 연결이 **전부 실패**하므로, 잠금(lock-out)을 막으려면 **원격 설정** 또는 **설치 프로그램 업데이트** 경로를 마련합니다.

- **구현**: 사용하는 HTTP 스택에 따라 `TrustManager`/`SSLContext` 커스터마이즈, 또는 **OkHttp Certificate Pinner** 등 라이브러리의 공식 pinning API를 사용합니다. (검증 끄기·빈 검증기는 사용하지 마세요.)

---

## 3. 에이전트 생명주기 (권장 순서)

1. **시작 시** `POST /api/agents/register` — 서버에 에이전트 등록(또는 갱신)
2. **주기적으로** `POST /api/agents/heartbeat` — 온라인 상태 유지(기본 타임아웃: 약 5분 미수신 시 오프라인 처리)
3. **데이터 전송**
   - 로컬 패킷 요약 등: `POST /api/traffic`
   - USB·프로세스·파일·브라우저 등 보안 이벤트: `POST /api/security-events`
4. **종료 시(선택)** `POST /api/agents/disconnect` — 즉시 오프라인 처리

---

## 4. API 상세

### 4.1 등록 — `POST /api/agents/register`

요청 본문 (`AgentRegisterRequest`):

| 필드 | 설명 |
|------|------|
| `agentName` | 에이전트 고유 ID (예: `DESKTOP-USER01`, README의 `agent_id`에 해당) |
| `hostname` | 컴퓨터 이름 |
| `ipAddress` | **이 PC의 IPv4** (아래 “카운터 연동” 참고) |
| `osType` | 예: `Windows` |
| `osVersion` | 예: `Windows 11` |
| `agentVersion` | BeaconGuardian 버전 문자열 |
| `username` | 로그온 사용자명 |
| `metadata` | 선택. JSON 문자열로 추가 정보(수집 모듈 버전 등) |

**응답 예시:**

```json
{
  "success": true,
  "message": "Agent registered successfully",
  "agentId": 1,
  "agentName": "DESKTOP-USER01"
}
```

### 4.2 하트비트 — `POST /api/agents/heartbeat`

```json
{ "agentName": "DESKTOP-USER01" }
```

### 4.3 연결 해제 — `POST /api/agents/disconnect`

```json
{ "agentName": "DESKTOP-USER01" }
```

### 4.4 트래픽 로그 — `POST /api/traffic`

클라이언트에서 캡처한 **로컬 흐름 요약**을 올릴 때 사용합니다. `TrafficLogRequest` 필드:

| 필드 | 타입 | 설명 |
|------|------|------|
| `sourceIp` | string | 출발 IP |
| `destinationIp` | string | 목적 IP |
| `sourcePort` | int | 출발 포트 |
| `destinationPort` | int | 목적 포트 |
| `protocol` | string | TCP/UDP 등 |
| `bytesTransferred` | long | 바이트 |
| `packetsTransferred` | long | 패킷 수 |
| `duration` | int | 지속 시간(초 등, 에이전트 정의에 맞게) |
| `rawData` | string | 선택. JSON 등 원본 요약 |

서버는 저장 후 **`sourceIp`가 등록된 에이전트의 `ipAddress`와 일치하면** 해당 에이전트의 `totalTrafficLogs`를 증가시킵니다.

### 4.5 보안 이벤트 — `POST /api/security-events`

USB 연결, 프로세스 이상, 파일 변경, 브라우저 기록 등은 **하나의 엔티티**로 저장합니다. 본문은 `SecurityEvent`와 동일한 구조입니다.

| 필드 | 필수 | 설명 |
|------|------|------|
| `eventType` | 예 | `USB_CONNECT`, `PROCESS_ALERT`, `FILE_CHANGE`, `BROWSER_HISTORY` 등 (에이전트에서 문자열 규약 정의) |
| `severity` | 예 | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` 등 |
| `sourceIp` | 예 | 이벤트 발생 호스트 IP — **등록 시 `ipAddress`와 맞출 것** |
| `destinationIp` | 선택 | 해당 시 |
| `location` | 선택 | 경로/장치명 등 |
| `protocol` | 예 | 의미 없으면 `unknown` 등 고정값 |
| `port` | 예 | 없으면 `0` |
| `status` | 예 | 예: `detected`, `blocked` |
| `description` | 선택 | 사람이 읽을 설명 |
| `metadata` | 선택 | **JSON 문자열** — 상세 필드(예: USB VID/PID, 프로세스명, URL) |
| `blocked` | 선택 | 기본 `true` |
| `riskScore` | 선택 | 기본 `0.0` |

`sourceIp`가 등록된 에이전트 IP와 일치하면 `totalEvents`가 증가합니다.

**metadata JSON 예시 (개념):**

```json
{
  "module": "usb",
  "vendorId": "1234",
  "productId": "5678",
  "serial": "..."
}
```

---

## 5. `sourceIp` / `ipAddress` 일치 (중요)

`incrementEventCountByIp` / `incrementTrafficCountByIp`는 **`ipAddress`로 에이전트를 찾습니다.**  
따라서:

- 등록 시 넣은 **`ipAddress`**와
- 트래픽·보안 이벤트에 넣는 **`sourceIp`**

가 **동일한 문자열**이어야 대시보드의 에이전트별 집계가 맞습니다.  
다중 NIC·VPN 환경에서는 “Beacon 서버가 보는 클라이언트 IP”와 동일한 값을 쓰도록 에이전트에서 선택 로직을 두는 것이 좋습니다.

---

## 6. 설정 파일 예시 (에이전트 측)

이 레포의 `config.yaml` 구조(`agent.py`가 읽는 키)에 맞춘 예시입니다. 엔드포인트는 `/api/agents`, `/api/traffic`, `/api/security-events`입니다.

```yaml
beacon:
  server_url: "https://192.168.0.10:8080"
  username: "admin"
  password: "환경변수 또는 비밀 저장소에서 로드"
  # 선택: IP 선택(outbound=서버 방향 라우트 기준, hostname=기존 방식)
  ip_selection: "outbound"
  # 선택: JWT exp 선제 갱신(초 단위, exp 몇 초 전에 재로그인)
  jwt_refresh_before_exp_seconds: 90
  # 선택: TLS (운영 권장)
  tls:
    require_https: true
    ca_bundle: "C:\\certs\\corp-ca.pem"   # 사내 CA 번들(없으면 OS 신뢰 저장소)
    client_cert: "C:\\certs\\agent.crt"  # mTLS
    client_key: "C:\\certs\\agent.key"
    pin_spki_sha256:                      # SPKI SHA256(hex), 복수 시 백업 핀
      - "abcdef0123456789..."             # openssl 등으로 사전 계산

# 선택. 없으면 기본값(에이전트 이름 BeaconGuardian, 하트비트 60초)
agent:
  agent_name: "DESKTOP-USER01"
  agent_version: "1.0.0"
  heartbeat_interval_seconds: 30

# 선택: 수집 모듈 on/off (기본 true)
collectors:
  usb: true
  network: true
  process: true
  filesystem: true
  browser_history: true

monitoring:
  usb_check_interval: 5
  network_check_interval: 10
  process_check_interval: 5
  browser_check_interval: 30
  include_traffic_raw_data: false   # true 시 트래픽에 rawData(JSON) 포함

paths:
  watch_dirs:
    - "C:\\Windows\\System32"

logging:
  level: "INFO"
  file: "agent.log"
```

- 로그인 후 받은 JWT는 **메모리에 보관**하고, 클라이언트는 JWT `exp`를 읽어 **만료 전에 재로그인**합니다.
- `heartbeat_interval_seconds`는 **5분(300초) 미만**으로 두는 것이 안전합니다(서버 기본 오프라인 판정과 맞춤). 코드에서는 **10~299초**로 보정합니다.
- `tls.require_https: true`이면 `server_url`은 반드시 `https://`여야 합니다.

---

## 7. Suricata와의 관계 (정리)

- **Suricata**: 네트워크 센서 쪽에서 `security_events` 등에 **IDS/트래픽 관련** 이벤트가 쌓일 수 있습니다.
- **BeaconGuardian**: **각 PC**에서 호스트 관점 데이터를 같은 DB/API로 보냅니다.
- 두 소스가 **동일한 IP**를 공유하면, 대시보드에서 같은 호스트 주변을 같이 볼 수 있습니다(에이전트 등록 IP·이벤트 `sourceIp` 일치 권장).

---

## 8. 문제 해결

| 증상 | 확인 |
|------|------|
| `401 Unauthorized` | 로그인 여부, `Authorization: Bearer` 형식, 토큰 만료 |
| `403` | 관리자 전용 API가 아닌지 확인 (`/api/agents` 등은 일반 인증 사용자면 됨 — 역할은 서버 설정 따름) |
| 에이전트 집계가 안 올라감 | 등록 `ipAddress`와 이벤트/트래픽 `sourceIp` 불일치 |
| 곧바로 오프라인 | 하트비트 간격이 5분 초과이거나, `disconnect` 호출 여부 |

---

## 9. 참고 (코드 위치)

- 에이전트 API: `com.example.beacon.controller.AgentController` (`/api/agents`)
- 트래픽: `TrafficController` (`POST /api/traffic`)
- 보안 이벤트: `SecurityEventController` (`POST /api/security-events`)
- 인증: `SecurityConfig`, `JwtAuthenticationFilter`

---

## 10. 이 레포(Python 에이전트) 구현 요약

**이 저장소 `src/`** 기준으로 가이드와의 대응입니다.

| 가이드 항목 | 상태 | 비고 |
|-------------|------|------|
| §2 로그인·JWT·`Bearer` | 구현됨 | `beacon_client.py` |
| §3 등록·하트비트·disconnect | 구현됨 | 동일 |
| §3 트래픽·보안 이벤트 | 구현됨 | `send_traffic`은 트래픽 전용 정규화(보안 이벤트 필드 혼입 없음) |
| §2.3 **HTTPS 강제** | 설정 시 | `beacon.tls.require_https: true`이면 `https://`만 허용 |
| §2.3 **mTLS** | 구현됨 | `beacon.tls.client_cert` / `client_key` |
| §2.4 **SPKI 핀닝** | 구현됨 | `beacon.tls.pin_spki_sha256`(리스트). `cryptography` 필요 |
| §2.3 JWT **만료 전 갱신** | 구현됨 | JWT `exp` 디코드 후 `jwt_refresh_before_exp_seconds` 전에 재로그인 |
| §4.4 `rawData` | 선택 | `monitoring.include_traffic_raw_data: true` 또는 `collectors.traffic_raw: true` |
| §4.5 `blocked` / `riskScore` | 구현됨 | 미지정 시 `blocked: true`, `riskScore: 0.0` |
| §4.5 `severity` | 정규화 | 전송 전 `LOW`/`MEDIUM` 등 대문자로 통일(별칭 매핑) |
| §5 **IP 선택** | 구현됨 | 기본 `beacon.ip_selection: outbound`(UDP 라우트 추정). `hostname`으로 예전 방식 가능 |
| §6 **`collectors`** | 구현됨 | `collectors.*` 로 모듈 on/off |
| §7 Suricata | 해당 없음 | 센서/서버 측 |
| §9 Java 클래스 | 서버 레포 | 백엔드 참고 |

**한계:** 핀닝은 **SPKI(SHA256)** 만 지원합니다. CA 번들·클라이언트 인증서 경로는 **절대 경로** 권장. JWT `exp` 클레임이 없는 토큰은 만료 선제 갱신이 동작하지 않을 수 있습니다.
