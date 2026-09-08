package xdrclient

import (
	"testing"
	"time"
)

func TestIsLoopbackEnrollmentHost(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"127.0.0.1:50051", "localhost:50051", "[::1]:50051"} {
		if !isLoopbackEnrollmentHost(h) {
			t.Fatalf("%s should be loopback", h)
		}
	}
	if isLoopbackEnrollmentHost(DefaultEnrollmentHost) {
		t.Fatal("prod enrollment host must use TLS")
	}
}

func TestProbeEnrollmentHostEmpty(t *testing.T) {
	t.Parallel()
	if err := ProbeEnrollmentHost("", time.Second); err == nil {
		t.Fatal("empty host")
	}
}
