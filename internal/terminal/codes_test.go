package terminal

import (
	"testing"

	"github.com/coder/websocket"
)

func TestParseSubprotocols(t *testing.T) {
	cases := []struct {
		name       string
		values     []string
		wantTicket string
		wantOK     bool
	}{
		{"two headers", []string{"pickle.terminal.v1", "ticket.abc123"}, "abc123", true},
		{"one comma-joined header", []string{"pickle.terminal.v1, ticket.xyz"}, "xyz", true},
		{"reversed order", []string{"ticket.z9", "pickle.terminal.v1"}, "z9", true},
		{"missing ticket", []string{"pickle.terminal.v1"}, "", false},
		{"missing name", []string{"ticket.abc", "other.thing"}, "", false},
		{"empty ticket value", []string{"pickle.terminal.v1", "ticket."}, "", false},
		{"three elements", []string{"pickle.terminal.v1", "ticket.a", "extra"}, "", false},
		{"nothing", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ticket, ok := parseSubprotocols(tc.values)
			if ok != tc.wantOK || ticket != tc.wantTicket {
				t.Fatalf("got (%q,%v) want (%q,%v)", ticket, ok, tc.wantTicket, tc.wantOK)
			}
		})
	}
}

func TestCloseCodeForReason(t *testing.T) {
	cases := map[string]websocket.StatusCode{
		reasonTicketInvalid:    closeTicketInvalid,
		reasonVMNotRunning:     closeVMNotRunning,
		reasonAccessRevoked:    closeAccessRevoked,
		reasonTerminalDisabled: closeDisabled,
		reasonSessionUnknown:   closeMaintenance,
		"SOMETHING_ELSE":       closeMaintenance, // unknown → 1001 fail-closed
	}
	for reason, want := range cases {
		if got := closeCodeForReason(reason); got != want {
			t.Errorf("reason %q: got %d want %d", reason, got, want)
		}
	}
}

func TestCloseMessagesPresentAndBounded(t *testing.T) {
	// Every close code must carry a Korean message short enough for a WS close
	// reason (<123 bytes) so it can double as the close-frame reason.
	for code, msg := range closeMessages {
		if msg == "" {
			t.Errorf("code %d has empty message", code)
		}
		if len(msg) >= 123 {
			t.Errorf("code %d message too long for close reason (%d bytes)", code, len(msg))
		}
	}
}
