package keystore

import "fmt"

func errUnsupported(backend string) error {
	return fmt.Errorf("keystore: backend %q not available on this platform/build", backend)
}
