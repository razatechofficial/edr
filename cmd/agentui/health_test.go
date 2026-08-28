package main

import "testing"

func TestIngestIdleBanner502(t *testing.T) {
	got := ingestIdleBanner(true, true, `rpc error: code = Unavailable desc = unexpected HTTP status code received from server: 502 (Bad Gateway)`)
	if got != "Cloud ingest is unavailable (502). The sensor is running on this Mac." {
		t.Fatalf("banner = %q", got)
	}
}

func TestIngestIdleBannerNotConfigured(t *testing.T) {
	got := ingestIdleBanner(false, false, "")
	if got != "Ingest is not configured. Local detections continue." {
		t.Fatalf("banner = %q", got)
	}
}
