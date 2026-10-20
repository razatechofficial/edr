package localapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAuthorizePeer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		peer    Peer
		credErr error
		wantErr error
	}{
		{
			name: "root is allowed",
			peer: Peer{PID: 4242, UID: 0, GID: 0},
		},
		{
			// The console user reaching the socket must not be able to isolate
			// the host.
			name:    "console user is refused",
			peer:    Peer{PID: 501, UID: 501, GID: 20},
			wantErr: ErrNotPrivileged,
		},
		{
			name:    "a service account is refused",
			peer:    Peer{PID: 9, UID: 1, GID: 1},
			wantErr: ErrNotPrivileged,
		},
		{
			// A transport that cannot name its caller is refused outright
			// rather than trusted.
			name:    "unnamed caller is refused",
			credErr: ErrPeerCredsUnsupported,
			wantErr: ErrPeerCredsUnsupported,
		},
		{
			name:    "a credential lookup failure is refused",
			credErr: fmt.Errorf("localapi: SO_PEERCRED: %w", errors.New("bad file descriptor")),
			wantErr: nil, // propagated verbatim; checked below
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := authorizePeer(tc.peer, tc.credErr)
			switch {
			case tc.credErr != nil:
				if err == nil {
					t.Fatal("a credential lookup failure must refuse the call")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantErr == nil:
				if err != nil {
					t.Fatalf("authorizePeer() = %v, want nil", err)
				}
			default:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			}
		})
	}
}

// TestAuthorizePeerMentionsTheCaller keeps the refusal useful in an audit log:
// "permission denied" without a uid and a pid names nobody.
func TestAuthorizePeerMentionsTheCaller(t *testing.T) {
	t.Parallel()
	err := authorizePeer(Peer{PID: 1234, UID: 501}, nil)
	if err == nil {
		t.Fatal("a non-root peer must be refused")
	}
	for _, want := range []string{"501", "1234"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q must name %q", err, want)
		}
	}
}
