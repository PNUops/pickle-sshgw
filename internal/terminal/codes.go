package terminal

import (
	"strings"

	"github.com/coder/websocket"
)

// Subprotocol is the fixed WS subprotocol name the bridge echoes. The browser
// offers exactly two elements — this fixed name plus a "ticket.<t>" element —
// and the bridge echoes ONLY this name (the ticket element is never echoed and
// the offered strings are never logged, to keep the ticket out of every log).
const Subprotocol = "pickle.terminal.v1"

// ticketPrefix marks the second, ticket-carrying subprotocol element.
const ticketPrefix = "ticket."

// WS close codes. 1000/1001 are the standard codes; 4000–4006 are Pickle
// application-private codes shared with the console (docs/plan/05-ssh-access.md,
// "종료 코드·한국어 메시지"). The console maps each to a Korean overlay.
const (
	closeNormal        = websocket.StatusNormalClosure // 1000 세션 종료
	closeMaintenance   = websocket.StatusGoingAway     // 1001 서버 점검
	closeTicketInvalid = websocket.StatusCode(4000)    // 티켓 무효·만료
	closeIdle          = websocket.StatusCode(4001)    // 15분 유휴
	closeForce         = websocket.StatusCode(4002)    // 관리자 강제 종료
	closeVMNotRunning  = websocket.StatusCode(4003)    // VM 미실행
	closeAccessRevoked = websocket.StatusCode(4004)    // 접근 권한 변경
	closeDisabled      = websocket.StatusCode(4005)    // 기능 비활성·점검
	closeConnFailed    = websocket.StatusCode(4006)    // 연결 실패
)

// Korean user-facing close messages, sent in the `exit` control frame just before
// the WS close. Kept short enough to double as the WS close reason (<123 bytes).
var closeMessages = map[websocket.StatusCode]string{
	closeNormal:        "세션이 종료되었습니다.",
	closeMaintenance:   "서버 점검 중입니다. 잠시 후 다시 연결해 주세요.",
	closeTicketInvalid: "터미널 티켓이 유효하지 않거나 만료되었습니다. 다시 시도해 주세요.",
	closeIdle:          "15분간 입력이 없어 세션을 종료했습니다.",
	closeForce:         "관리자에 의해 세션이 종료되었습니다.",
	closeVMNotRunning:  "VM이 실행 중이 아닙니다.",
	closeAccessRevoked: "접근 권한이 변경되어 세션을 종료했습니다.",
	closeDisabled:      "웹 터미널 기능이 비활성화되었습니다.",
	closeConnFailed:    "연결에 실패했습니다. 잠시 후 다시 시도해 주세요.",
}

// closeMessage returns the Korean message for a close code, or a generic fallback.
func closeMessage(code websocket.StatusCode) string {
	if m, ok := closeMessages[code]; ok {
		return m
	}
	return "세션이 종료되었습니다."
}

// closeReason is the ASCII-safe short reason string put on the WS close frame
// (the Korean text travels in the `exit` control frame). The close frame reason is
// only for logs/protocol; the console renders the `exit` message.
func closeReason(code websocket.StatusCode) string {
	return "pickle-terminal"
}

// Reason codes returned by pickle-api on a redeem/revalidate deny
// (docs/api/internal.md Link 3). SESSION_UNKNOWN is revalidate-only.
const (
	reasonTicketInvalid    = "TICKET_INVALID"
	reasonVMNotRunning     = "VM_NOT_RUNNING"
	reasonAccessRevoked    = "ACCESS_REVOKED"
	reasonTerminalDisabled = "TERMINAL_DISABLED"
	reasonSessionUnknown   = "SESSION_UNKNOWN"
)

// closeCodeForReason maps a pickle-api deny reason to its WS close code. An
// unrecognised reason maps to 1001 (fail-closed: treat as a server-side condition
// worth a reconnect prompt rather than leaking an unmapped state).
func closeCodeForReason(reason string) websocket.StatusCode {
	switch reason {
	case reasonTicketInvalid:
		return closeTicketInvalid
	case reasonVMNotRunning:
		return closeVMNotRunning
	case reasonAccessRevoked:
		return closeAccessRevoked
	case reasonTerminalDisabled:
		return closeDisabled
	case reasonSessionUnknown:
		return closeMaintenance
	default:
		return closeMaintenance
	}
}

// parseSubprotocols extracts the ticket from the offered Sec-WebSocket-Protocol
// elements. The contract requires exactly two elements — the fixed Subprotocol
// name and a single "ticket.<t>" element — in that set. It returns the ticket and
// ok=true only when both are present and the ticket is non-empty. The offered
// strings themselves are never returned for logging (they carry the ticket).
//
// values are the raw header values; a single header may itself be a
// comma-separated list, so each value is split.
func parseSubprotocols(values []string) (ticket string, ok bool) {
	var tokens []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if t := strings.TrimSpace(part); t != "" {
				tokens = append(tokens, t)
			}
		}
	}
	if len(tokens) != 2 {
		return "", false
	}
	var sawName bool
	for _, t := range tokens {
		switch {
		case t == Subprotocol:
			sawName = true
		case strings.HasPrefix(t, ticketPrefix):
			ticket = strings.TrimPrefix(t, ticketPrefix)
		}
	}
	if !sawName || ticket == "" {
		return "", false
	}
	return ticket, true
}
