# BeaconGuardian 방화벽 연동 설계 (A+B 하이브리드)

## 1. 목표

서버가 **무엇을 막을지**의 단일 진실 소스(SSoT)를 유지한다.  
에이전트는 (1) **즉시 반영 가능한 푸시 명령(B)** 과 (2) **주기적 전체 정합(desired state, A)** 을 모두 수행해, 지연·누락·재시작에 강하게 만든다.

## 2. 원칙

| 원칙 | 설명 |
|------|------|
| Idempotent | 같은 규칙을 여러 번 적용해도 결과가 같아야 한다. |
| 서버 `ruleId` 기준 | 로컬 방화벽 규칙은 서버 발급 `ruleId`(또는 `syncToken`)와 매핑한다. |
| B는 A를 대체하지 않음 | 푸시는 빠른 적용, 동기화는 최종 일치 보장. |
| 관리 범위 분리 | `BeaconGuardian/` 접두 등으로 에이전트가 만든 규칙만 수정·삭제한다. |

## 3. 전체 구조

```
[서버]  정책/방화벽 규칙 DB
   │    ├─ (B) 실시간 채널: 명령 큐 또는 SSE/WebSocket
   │    └─ (A) REST: desired state 스냅샷
   ▼
[에이전트]  수신 → 로컬 큐 → WFAS 적용 모듈 → 적용 결과 보고(선택)
   │                    ▲
   └─ 주기 타이머 ──────┘ (A 재동기화)
```

- **B**: “지금 이 규칙 추가/삭제해” 같은 델타 명령.
- **A**: “현재 이 에이전트에 해당하는 전체 목표 규칙 집합” 스냅샷.

## 4. 서버 측 구성 요소

### 4.1 기존 자산

`firewall_rules`(또는 동등 테이블) + 에이전트 식별(`sourceIp` / `agentName` / 추후 `agentId`).

### 4.2 추가 개념

- **FirewallDesiredRevision**: 서버가 발급하는 단조 증가 리비전(에이전트별 또는 전역). A 응답에 `revision` 포함.
- B 명령마다 `revision` 증가 또는 별도 `commandId`로 순서 보장.
- **AgentFirewallCursor** (DB): 에이전트가 마지막으로 확인한 `revision` / `lastSyncAt` (선택, 운영 가시성).

### 4.3 채널 B — 실시간(또는 준실시간)

**옵션 1 (권장, 구현 단순): Long Poll / SSE**

- `GET /api/agents/me/firewall-commands?since={cursor}`
- 서버는 대기 후 새 명령이 생기면 즉시 반환(롱폴), 또는 SSE로 스트림.

명령 예시 JSON:

```json
{
  "commandId": "uuid",
  "revision": 1042,
  "action": "UPSERT_RULE | DELETE_RULE | ENABLE_PROFILE | NOOP",
  "payload": { "ruleId": 55 }
}
```

**옵션 2: WebSocket** — 동일 페이로드, 양방향 + 하트비트.

트리거: 기존 `createAgentEvent` / 정책 엔진에서 `createBlockRuleForIp` 직후 같은 트랜잭션 또는 직후에 해당 에이전트에게만 B 명령 enqueue.

### 4.4 채널 A — 주기 스냅샷

- `GET /api/agents/me/firewall-desired-state`  
- 인증: 기존 JWT, 주체 = 로그인 사용자와 매핑된 에이전트(또는 `agentName` 쿼리 + 소유 검증).

응답 예시:

```json
{
  "revision": 1042,
  "rules": [
    {
      "ruleId": 55,
      "action": "block",
      "remoteAddresses": ["203.0.113.10"],
      "direction": "outbound",
      "protocol": "any",
      "enabled": true,
      "displayName": "AUTO-BLOCK 203.0.113.10"
    }
  ],
  "firewallProfiles": { "domain": "on", "private": "on", "public": "on" }
}
```

에이전트 로직: 로컬에 저장된 `revision` < 서버 `revision`이면 전체 목록으로 재동기화(추가/삭제 diff).

### 4.5 적용 결과 보고 (선택)

`POST /api/agents/me/firewall-status`

```json
{
  "lastAppliedRevision": 1042,
  "errors": [],
  "localRuleIds": ["..."]
}
```

서버는 대시보드에서 “에이전트 적용 성공/실패” 표시.

## 5. 에이전트(BeaconGuardian) 측

### 5.1 모듈

| 모듈 | 역할 |
|------|------|
| `FirewallCommandReceiver` | B 채널 수신(스레드/비동기), 내부 우선순위 큐에 넣음 |
| `FirewallDesiredStateSync` | A 주기 호출(예: 60~300초) + 시작 시 1회 |
| `WindowsFirewallApplier` | PowerShell/netsh로 WFAS 반영, Beacon 접두 규칙만 관리 |
| `LocalStateStore` | `lastRevision`, 로컬 `ruleId` ↔ 서버 `ruleId` 매핑 (JSON, `%ProgramData%` 등) |

구현 위치: `src/firewall/` (에이전트 저장소 기준).

### 5.2 처리 순서 (한 사이클)

1. 시작 시: A 호출 → 전체 적용 → `lastRevision` 저장.
2. 백그라운드: B 수신 시 큐에 넣고 즉시 적용 시도.
3. 주기: A 호출 → 서버 `revision`과 로컬 비교 → 불일치 시 전체 reconcile(A가 진실).
4. B 실패 시: 로그만 남기지 말고 다음 A 주기에 수습.

### 5.3 B와 A의 관계 (충돌 방지)

- 항상 **A의 스냅샷이 최종 승자**.
- B는 빠른 미리 적용; 이후 A가 같은 `ruleId` 집합으로 덮어써서 일치시킴.
- 동일 `ruleId`에 대해 B가 DELETE, A가 아직 포함 → A 다음 주기에 삭제 반영.

## 6. 보안·운영

- TLS + JWT 유지. B/SSE도 동일 인증.
- 관리자 권한: 에이전트 서비스를 로컬 시스템/관리자로 실행하거나, 방화벽 API용 별도 상승 작업.
- 잠금 방지: 에이전트→서버 URL/IP, 관리 RDP/SSH 등은 서버 정책 + 로컬 예외 목록으로 항상 허용.
- 감사: 적용 전후 `ruleId`·`revision` 로깅.

## 7. 실패 시나리오

| 상황 | 동작 |
|------|------|
| B만 실패 | 다음 A로 복구 |
| A만 실패(네트워크) | B로 일부 유지, A 재시도 백오프 |
| 에이전트 재시작 | 로컬 `lastRevision` + A 풀 동기화 |
| 서버 롤백 규칙 | A 스냅샷에 없으면 로컬에서 삭제 |

## 8. 구현 단계 (권장)

1. **A**: `GET` desired-state + 에이전트 reconcile — 구현됨.
2. **B**: 서버가 명령 enqueue + 에이전트 롱폴(`fetch_firewall_commands`) — 구현됨(로컬 `last_command_id` 커서).
3. **상태 보고**: `report_status` 기본 `true` 시 `POST /api/agents/me/firewall-status`.

## 9. 서버·운영 주의

- **agentName**: 방화벽 관련 API는 쿼리 `?agentName=` 에 `config.agent.agent_name` 과 동일한 값을 붙입니다. 동일 계정에 PC가 여러 대일 때 서버가 요구하는 경우가 있습니다.
- **소유자(owner)**: JWT 사용자에게 등록된 에이전트에 `ownerUserId`가 연결되지 않으면 `/api/agents/me/*` 가 404일 수 있습니다. 관리자가 `PUT /api/admin/agents/{id}/owner` 등으로 소유를 연결한 뒤 사용합니다.

## 10. 설정 (`config.yaml`)

```yaml
firewall:
  enabled: false
  sync_interval_seconds: 120
  rule_name_prefix: "BeaconGuardian/"
  state_file: ""   # 비우면 %ProgramData%/BeaconGuardian/firewall_state.json
  report_status: true    # POST /api/agents/me/firewall-status (대시보드 연동 시 권장)
  channel_b: true        # 롱폴 B 채널
  long_poll_seconds: 75  # firewall-commands HTTP 타임아웃(롱폴 길이)
  command_poll_backoff_seconds: 30   # 404/미구현 시 재시도 간격
```

`firewall_state.json` 에 `last_revision`, `local_rule_ids`, **`last_command_id`**(B 커서)가 저장됩니다.

Windows가 아니거나 `enabled: false`이면 방화벽 모듈은 동작하지 않는다.
