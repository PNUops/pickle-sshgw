# pickle-sshgw

Pickle(피클)은 부산대학교 구성원을 위한 셀프서비스 클라우드 플랫폼 **PNU Cloud**(정식 명칭: 부산대학교 클라우드 플랫폼)의 코드네임이다. 사용자가 웹
콘솔에서 VM을 신청하면 관리자 승인 후 Proxmox VE에 자동 프로비저닝되며, SSH 접속과
도메인 기반 HTTP(S) 공개까지 제공한다. 이 저장소는 그중 **SSH 게이트웨이**를 담당한다.

## 역할

사용자는 `ssh <vm슬러그>@ssh.pickle.pnuops.com` 형식으로 접속하며, 게이트웨이는
사용자명으로 전달된 VM 슬러그를 대상 VM으로 라우팅한다. 개인 식별은 사용자가 콘솔에
등록한 SSH 공개키로 이루어진다. 캠퍼스 방화벽은 인바운드를 차단하므로 오프캠퍼스
접속은 릴레이를 경유한다. 릴레이의 HAProxy(`mode tcp`, `send-proxy-v2`)가 공개 `:22`
연결을 캠퍼스가 **아웃바운드**로 개통한 WireGuard 터널로 넘기고, 터널 반대편의
게이트웨이가 이를 수신한다. 각 VM의 호스트키는 수집 시점에 핀 고정되어 이후 접속에서
검증된다.

접속 경로:
`client → HAProxy(send-proxy-v2) → WireGuard 터널 → sshgw-proxyfront:22
(PROXY 필수, 피어 전용) → sshpiperd:2222(loopback) → route-plugin → VM:22`

## 구성 바이너리

게이트웨이 LXC 안에서 세 개의 프로세스가 동작한다. 커스텀 Go 바이너리 세 종은 이
저장소에서 빌드하고, `sshpiperd`는 오픈소스 업스트림(`github.com/tg123/sshpiper`)의
고정 버전 바이너리를 수정 없이 그대로 쓴다. 아래 라우팅 플러그인이 같은 고정 버전을
`libplugin` 모듈로 임포트하므로, 업스트림 버전은 이 저장소의 `go.mod` 직접 의존성이기도
하다(바이너리와 플러그인 SDK 버전은 반드시 함께 올린다).

1. **`sshgw-proxyfront`** (`cmd/sshgw-proxyfront`, `internal/proxyfront`) — `:22`
   인그레스 프런트 심. **PROXY protocol v2 헤더를 필수로 수용**한다(REQUIRE 정책,
   WireGuard 피어로 한정). 헤더가 없거나 손상됐거나 피어가 아닌 출처에서 온 연결은 SSH
   바이트를 한 바이트도 교환하지 않고 즉시 끊으며, 원시 TCP 출처로 폴백하지 않는다.
   유효한 연결에 대해서는 복원한 실제 클라이언트 IP를 담아 새 PROXY v2 헤더를 loopback
   sshpiperd로 재발행한 뒤 바이트를 1:1로 중계한다. (업스트림 sshpiperd의
   `--allowed-proxy-addresses`는 헤더를 선택으로 두는 deprecated *lax* 정책만 제공해
   헤더 없는 연결을 원시로 처리하므로, 그 공백을 이 심이 메운다.)

2. **`sshgw-route-plugin`** (`cmd/sshgw-route-plugin`, `internal/gateway`,
   `internal/route`) — sshpiperd의 gRPC 라우팅 플러그인. SSH 사용자명을 VM 슬러그로,
   연결에서 실제 클라이언트 IP를 읽어 pickle-api의 내부 라우트 API
   (`POST /internal/sshgw/route`, Bearer 토큰)를 호출하고, 응답으로 받은 사용자로 대상
   VM에 파이핑한다. 라우트 조회가 거부되거나 오류가 나면 세션을 거절한다. 기동 자체도
   fail-closed다. 공유 토큰(`PICKLE_SSHGW_TOKEN`)이 비었거나, pickle-api 베이스
   URL(`PICKLE_SSHGW_API_BASE`, 이 프로세스에는 기본값이 없다)이 비었거나, 게이트웨이→VM
   홉에 쓰는 업스트림 개인키 파일을 읽을 수 없거나 형식이 잘못됐으면 플러그인은 아예
   기동하지 않는다.

3. **`sshgw-terminal-bridge`** (`cmd/sshgw-terminal-bridge`, `internal/terminal`)
   — 웹 터미널 WebSocket 종단(`172.30.1.30:8082`)과 제어 포트(`172.30.1.30:8083`)를
   여는 저권한 데몬. 두 리스너 모두 와일드카드가 아니라 게이트웨이 LXC의 내부 주소
   하나에만 바인드한다. 브라우저 WS를 잠금 SSH 연결로 VM에 중계한다. 원타임 티켓
   redeem, 60초 주기
   재검증, 세션 감사는 pickle-api에 위임하며, 이 데몬은 DB·Proxmox 토큰·자격증명 암호
   키를 일절 보유하지 않는다. 제어 포트는 pickle-api의 강제 종료 호출을 처리한다.

`sshpiperd`는 업스트림 v1.5.4를 `127.0.0.1:2222`에서 loopback으로 구동하며
(`--allowed-proxy-addresses 127.0.0.1/32`), 위 라우팅 플러그인과 함께 scp/sftp/VSCode
Remote가 그대로 동작하는 투명 SSH 파이핑을 수행한다.

## 구성 요소·버전

- **Go 1.26** (`go.mod`: `go 1.26.0`)
- **sshpiperd v1.5.4** — 버전 고정. 오픈소스 업스트림 바이너리이자 `libplugin` 모듈 의존성

`go.mod` 직접 의존성 전체:

| 모듈 | 버전 | 용도 |
|---|---|---|
| `github.com/tg123/sshpiper` | v1.5.4 | sshpiperd 플러그인 SDK (`libplugin`) |
| `github.com/coder/websocket` | v1.8.15 | 터미널 브리지의 WebSocket 종단 |
| `github.com/pires/go-proxyproto` | v0.15.0 | proxyfront의 PROXY protocol v2 수용·재발행 |
| `golang.org/x/crypto` | v0.54.0 | SSH 클라이언트·ed25519 키 처리 |
| `github.com/urfave/cli/v2` | v2.27.7 | 세 바이너리의 플래그·환경변수 파싱 |
| `github.com/sirupsen/logrus` | v1.9.4 | 구조화 로깅 |

## 빌드·검증

```bash
scripts/setup-hooks.sh   # 최초 1회: git 훅 설치
scripts/verify.sh        # shellcheck → gofmt → go vet → build → test → 공개 위생 검사
scripts/build.sh         # → dist/ 에 바이너리 3종 생성
```

## systemd 유닛

`scripts/systemd/` 의 세 유닛 파일(`sshpiperd.service`, `sshgw-proxyfront.service`,
`sshgw-terminal-bridge.service`)이 게이트웨이 서비스 정의의 **단일 출처**다. 게이트웨이
호스트에는 이 파일들을 `/etc/systemd/system/` 으로 복사한 뒤 `systemctl daemon-reload`
로 반영한다. 세 서비스 모두 비-root `pickle` 계정으로 동작한다(proxyfront는 `:22`
바인드를 위해 `CAP_NET_BIND_SERVICE`만 추가로 갖는다). 토큰을 쓰는 두 서비스
(route-plugin을 띄우는 sshpiperd, terminal-bridge)는 토큰이 없으면 기동하지
않는다(fail-closed). 배포 자동화는 유닛 파일 동기화를 바이너리 교체와 같은 단계에서
수행해야 한다. 유닛 파일만 고치고 배포에서 동기화하지 않으면 실행 중인 서비스에는
아무 변화가 없다.

## 환경 변수 (`/etc/pickle/sshgw.env`)

시크릿 값은 이 저장소에 포함되지 않는다. 모든 변수는 동명의 CLI 플래그로도 줄 수 있다.

| 변수 | 사용처 | 의미 | 기본값 |
|---|---|---|---|
| `PICKLE_SSHGW_API_BASE` | route-plugin, bridge | pickle-api 베이스 URL. **두 프로세스의 동작이 다르다** — bridge는 기본값이 있어 미설정으로도 뜨지만, route-plugin은 기본값이 없어 비어 있으면 기동을 거부한다 | bridge `http://172.30.1.20:8080` / route-plugin 없음(필수) |
| `PICKLE_SSHGW_TOKEN` | route-plugin, bridge | pickle-api 내부 API 호출용 공유 Bearer 토큰 | 없음 (미설정 시 fail-closed) |
| `PICKLE_SSHGW_UPSTREAM_KEY_FILE` | route-plugin | 게이트웨이→VM 홉에 쓰는 플랫폼 ed25519 개인키 파일. 읽기 실패·형식 오류도 fail-closed | `/etc/pickle/sshgw/upstream_ed25519_key` |
| `PICKLE_SSHGW_TIMEOUT` | route-plugin | 라우트 조회 1회의 HTTP 타임아웃 (API가 멎어도 SSH 연결이 매달리지 않게 한다) | `5s` |
| `SSHGW_PROXYFRONT_LISTEN` | proxyfront | `:22` 인그레스 주소 (WireGuard 인터페이스 주소에 바인드) | `10.100.100.2:22` |
| `SSHGW_PROXYFRONT_UPSTREAM` | proxyfront | loopback sshpiperd 주소 | `127.0.0.1:2222` |
| `SSHGW_PROXYFRONT_PEER` | proxyfront | 신뢰 WireGuard 피어 CIDR (여기서 온 유효 PROXY 헤더만 수용) | `10.100.100.1/32` |
| `PICKLE_TERMINAL_WS_LISTEN` | bridge | 브라우저 WS 인그레스 주소 | `172.30.1.30:8082` |
| `PICKLE_TERMINAL_CONTROL_LISTEN` | bridge | api→bridge 제어 포트 주소 | `172.30.1.30:8083` |
| `PICKLE_TERMINAL_CONTROL_TOKEN` | bridge | 인바운드 제어 Bearer (게이트웨이 토큰과 별개로 독립 폐기 가능) | 없음 (미설정 시 fail-closed) |
| `PICKLE_TERMINAL_CONSOLE_ORIGIN` | bridge | WS 핸드셰이크에서 정확히 일치해야 하는 브라우저 Origin | `https://pickle.pnuops.com` |
| `PICKLE_TERMINAL_KEY_FILE` | bridge | 플랫폼 터미널 ed25519 개인키 파일 경로. 읽기 실패·형식 오류도 fail-closed | `/etc/pickle/sshgw/terminal_ed25519_key` |
| `PICKLE_TERMINAL_WS_PEER` | bridge | WS 인그레스에 도달할 수 있는 유일한 TCP 피어 IP (nginx TLS 계층) | `172.30.1.10` |
| `PICKLE_TERMINAL_CONTROL_PEER` | bridge | 제어 포트에 도달할 수 있는 유일한 TCP 피어 IP (pickle-api) | `172.30.1.20` |
| `PICKLE_TERMINAL_IDLE_TIMEOUT` | bridge | 클라이언트 **입력**이 없을 때 세션을 닫기까지의 시간 (resize·ping은 초기화하지 않음) | `15m` |
| `PICKLE_TERMINAL_PING_INTERVAL` | bridge | 서버 측 WS ping 주기 | `30s` |
| `PICKLE_TERMINAL_REVALIDATE_INTERVAL` | bridge | pickle-api 재검증 폴링 주기 | `60s` |
| `PICKLE_TERMINAL_MAX_FRAME` | bridge | WS 수신(client→bridge) 프레임 상한 바이트. 큰 붙여넣기가 세션을 끊지 않도록 1MiB로 잡았다 | `1048576` |
| `PICKLE_TERMINAL_MAX_SESSIONS` | bridge | 브리지 전역 동시 세션 하드 상한 | `200` |

## 커밋 규약

커밋 메시지는 `type: subject` 형식, 영어 명령형, 72자 이내로 작성한다(마침표로 끝내지
않음). `type`은 feat, fix, docs, test, chore, refactor, perf, build, style, ci,
revert, merge 중 하나다. commit-msg 훅이 이 규칙을 강제한다.

`scripts/hygiene.sh`는 이 저장소가 공개물이라는 전제를 검사한다 — 비공개 문서 저장소나 인프라 저장소를 가리키는 참조, 내부 진행 표기(마일스톤·웨이브 등)가 있으면 검증이 실패한다. 수동 점검이 두 차례 위반을 놓친 뒤 자동화했다.
