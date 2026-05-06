//go:build windows

package collector

import "testing"

func TestPwshChannelStateSaveBookmarkAtomic_NoHandleNoPath(t *testing.T) {
	t.Parallel()
	st := &pwshChannelState{}
	if err := st.saveBookmarkAtomic(); err != nil {
		t.Fatalf("expected nil for noop save, got %v", err)
	}
}

