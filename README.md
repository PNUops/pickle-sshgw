# pickle-sshgw

Pickle(피클)은 부산대학교 구성원을 위한 셀프서비스 클라우드 플랫폼이다. 사용자가 웹
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
저장소에서 빌드하고, `sshpiperd`는 고정 버전의 stock 상용 바이너리를 그대로 쓴다.

1. **`sshgw-proxyfront`** (`cmd/sshgw-proxyfront`, `internal/proxyfront`) — `:22`
   인그레스 프런트 심. **PROXY protocol v2 헤더를 필수로 수용**한다(REQUIRE 정책,
   WireGuard 피어로 한정). 헤더가 없거나 손상됐거나 피어가 아닌 출처에서 온 연결은 SSH
   바이트를 한 바이트도 교환하지 않고 즉시 끊으며, 원시 TCP 출처로 폴백하지 않는다.
   유효한 연결에 대해서는 복원한 실제 클라이언트 IP를 담아 새 PROXY v2 헤더를 loopback
   sshpiperd로 재발행한 뒤 바이트를 1:1로 중계한다. (stock sshpiperd의
   `--allowed-proxy-addresses`는 헤더를 선택으로 두는 deprecated *lax* 정책만 제공해
   헤더 없는 연결을 원시로 처리하므로, 그 공백을 이 심이 메운다.)

2. **`sshgw-route-plugin`** (`cmd/sshgw-route-plugin`, `internal/gateway`,
   `internal/route`) — sshpiperd의 gRPC 라우팅 플러그인. SSH 사용자명을 VM 슬러그로,
   연결에서 실제 클라이언트 IP를 읽어 pickle-api의 내부 라우트 API
   (`POST /internal/sshgw/route`, Bearer 토큰)를 호출하고, 응답으로 받은 사용자로 대상
   VM에 파이핑한다. 거부·오류·토큰 미설정 시 세션을 거절하며, 토큰이 없으면 아예
   기동하지 않는다(fail-closed).

3. **`sshgw-terminal-bridge`** (`cmd/sshgw-terminal-bridge`, `internal/terminal`)
   — 웹 터미널 WebSocket 종단(`:8082`)과 제어 포트(`:8083`)를 여는 저권한 데몬.
   브라우저 WS를 잠금 SSH 연결로 VM에 중계한다. 원타임 티켓 redeem, 60초 주기
   재검증, 세션 감사는 pickle-api에 위임하며, 이 데몬은 DB·Proxmox 토큰·자격증명 암호
   키를 일절 보유하지 않는다. 제어 포트는 pickle-api의 강제 종료 호출을 처리한다.

`sshpiperd`는 stock v1.5.4를 `127.0.0.1:2222`에서 loopback으로 구동하며
(`--allowed-proxy-addresses 127.0.0.1/32`), 위 라우팅 플러그인과 함께 scp/sftp/VSCode
Remote가 그대로 동작하는 투명 SSH 파이핑을 수행한다.

## 구성 요소·버전

- **Go 1.26**
- **sshpiperd v1.5.4** (버전 고정, stock 업스트림 바이너리)
- `go-proxyproto` v0.15.0

## 빌드·검증

```bash
scripts/setup-hooks.sh   # 최초 1회: git 훅 설치
scripts/verify.sh        # shellcheck → gofmt → go vet → build → test
scripts/build.sh         # → dist/ 에 바이너리 3종 생성
```

## 환경 변수 (`/etc/pickle/sshgw.env`)

시크릿 값은 이 저장소에 포함되지 않는다.

| 변수 | 사용처 | 의미 |
|---|---|---|
| `PICKLE_SSHGW_API_BASE` | route-plugin, bridge | pickle-api 베이스 URL |
| `PICKLE_SSHGW_TOKEN` | route-plugin, bridge | 공유 Bearer 토큰 (미설정 시 fail-closed) |
| `SSHGW_PROXYFRONT_LISTEN` | proxyfront | 인그레스 주소 (기본 WireGuard 주소:22) |
| `SSHGW_PROXYFRONT_UPSTREAM` | proxyfront | loopback sshpiperd (기본 `127.0.0.1:2222`) |
| `SSHGW_PROXYFRONT_PEER` | proxyfront | 신뢰 WireGuard 피어 CIDR |
| `PICKLE_TERMINAL_WS_LISTEN` | bridge | 브라우저 WS 인그레스 주소 (기본 `:8082`) |
| `PICKLE_TERMINAL_CONTROL_LISTEN` | bridge | 제어 포트 주소 (기본 `:8083`) |
| `PICKLE_TERMINAL_CONTROL_TOKEN` | bridge | 인바운드 제어 Bearer (미설정 시 fail-closed) |
| `PICKLE_TERMINAL_CONSOLE_ORIGIN` | bridge | 허용 브라우저 Origin |
| `PICKLE_TERMINAL_KEY_FILE` | bridge | 플랫폼 터미널 ed25519 키 파일 경로 |

## 커밋 규약

커밋 메시지는 `type: subject` 형식, 영어 명령형, 72자 이내로 작성한다(마침표로 끝내지
않음). `type`은 feat, fix, docs, test, chore, refactor, perf, build, style, ci,
revert, merge 중 하나다. commit-msg 훅이 이 규칙을 강제한다.
