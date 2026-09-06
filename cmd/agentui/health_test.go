package main

import "testing"

func TestIngestIdleBanner502(t *testing.T) {
	got := ingestIdleBanner(true, true, `rpc error: code = Unavailable desc = unexpected HTTP status code received from server: 502 (Bad Gateway)`)
	if got != "Cloud ingest is unavailable (502). Local detections continue." {
		t.Fatalf("banner = %q", got)
	}
}

func TestIngestNeedsEnroll(t *testing.T) {
	if !ingestNeedsEnroll(operatorStatus{IngestFault: "device credentials required; enroll this PC first"}) {
		t.Fatal("missing cert must send the operator to Enroll")
	}
	if ingestNeedsEnroll(operatorStatus{IngestFault: "rpc error: 502 Bad Gateway"}) {
		t.Fatal("cloud 502 must stay on Retry stream")
	}
}

func TestIngestIdleBannerNotConfigured(t *testing.T) {
	got := ingestIdleBanner(false, false, "")
	if got != "Ingest is not configured. Local detections continue." {
		t.Fatalf("banner = %q", got)
	}
}
