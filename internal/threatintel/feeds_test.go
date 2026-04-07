package threatintel

import "testing"

func TestGuessIndicatorType(t *testing.T) {
	t.Parallel()
	if got := guessIndicatorType("1.1.1.1"); got != "ip" {
		t.Fatalf("got %s", got)
	}
	if got := guessIndicatorType("example.org"); got != "domain" {
		t.Fatalf("got %s", got)
	}
}
