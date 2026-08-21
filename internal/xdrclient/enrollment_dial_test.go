package xdrclient

import "testing"

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
