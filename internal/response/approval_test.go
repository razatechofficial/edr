package response

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/detection"
)

func TestAutoApproval(t *testing.T) {
	t.Parallel()
	g := &AutoApprovalGateway{}
	ok, err := g.RequestApproval(context.Background(), detection.Detection{}, PlaybookYAML{})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestFileApproval_Approve(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g := &FileApprovalGateway{ApprovalDir: dir, Interval: 20 * time.Millisecond}
	d := detection.Detection{ID: "aid1"}
	errCh := make(chan error, 1)
	approveCh := make(chan bool, 1)
	go func() {
		ok, err := g.RequestApproval(context.Background(), d, PlaybookYAML{ID: "P"})
		errCh <- err
		approveCh <- ok
	}()
	time.Sleep(50 * time.Millisecond)
	_ = os.WriteFile(filepath.Join(dir, "aid1.approve"), []byte("ok"), 0o600)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !(<-approveCh) {
		t.Fatal("expected approve true")
	}
}

func TestFileApproval_Reject(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g := &FileApprovalGateway{ApprovalDir: dir, Interval: 20 * time.Millisecond}
	d := detection.Detection{ID: "aid2"}
	errCh := make(chan error, 1)
	resCh := make(chan bool, 1)
	go func() {
		ok, err := g.RequestApproval(context.Background(), d, PlaybookYAML{ID: "P"})
		errCh <- err
		resCh <- ok
	}()
	time.Sleep(50 * time.Millisecond)
	_ = os.WriteFile(filepath.Join(dir, "aid2.reject"), []byte("n"), 0o600)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if <-resCh {
		t.Fatal("expected false")
	}
}

func TestFileApproval_Timeout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g := &FileApprovalGateway{ApprovalDir: dir, Interval: 20 * time.Millisecond}
	d := detection.Detection{ID: "aid3"}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err := g.RequestApproval(ctx, d, PlaybookYAML{ID: "P"})
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
}
