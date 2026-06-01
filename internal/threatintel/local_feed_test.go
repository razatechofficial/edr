package threatintel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalFeedCSV(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "ips.csv")
	if err := os.WriteFile(path, []byte("ip,mask,type,source,severity,tags,description,notes\n1.2.3.4,,malicious,test,high,,,\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	feed := NewLocalFeed("test-local", path, "csv")
	indicators, err := feed.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(indicators) != 1 || indicators[0].Value != "1.2.3.4" {
		t.Fatalf("indicators = %+v", indicators)
	}
}
