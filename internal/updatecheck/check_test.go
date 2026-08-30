package updatecheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompare(t *testing.T) {
	if Compare("1.0.0", "1.1.0") >= 0 {
		t.Fatal("older")
	}
	if Compare("1.2.0", "1.2.0") != 0 {
		t.Fatal("equal")
	}
	if Compare("prod-1", "prod-1") != 0 {
		t.Fatal("git equal")
	}
	if Compare("prod-1", "prod-2") != -1 {
		t.Fatal("git differ")
	}
}

func TestCompareVersion(t *testing.T) {
	cmp, err := compareVersion("1.0.0", "1.1.0")
	if err != nil || cmp >= 0 {
		t.Fatalf("1.0.0 vs 1.1.0 = %d %v", cmp, err)
	}
	cmp, err = compareVersion("1.2.0", "1.2.0")
	if err != nil || cmp != 0 {
		t.Fatalf("equal = %d %v", cmp, err)
	}
	cmp, err = compareVersion("v2.0.0", "1.9.9")
	if err != nil || cmp <= 0 {
		t.Fatalf("v2 vs 1.9.9 = %d %v", cmp, err)
	}
}

func TestCheckEmptyURL(t *testing.T) {
	r := Check("1.0.0", "", nil)
	if r.Update || r.Skipped == "" {
		t.Fatalf("%+v", r)
	}
}

func TestCheckCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"product":"EDR Agent","latest":"1.2.0","notes_url":"https://example.invalid"}`))
	}))
	defer srv.Close()
	r := Check("1.0.0", srv.URL, srv.Client())
	if !r.Update || r.Latest != "1.2.0" {
		t.Fatalf("%+v", r)
	}
	r = Check("1.2.0", srv.URL, srv.Client())
	if r.Update {
		t.Fatalf("current latest should not update: %+v", r)
	}
}
