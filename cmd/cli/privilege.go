package main

import "fmt"

func requirePrivileged() error {
	if processPrivileged() {
		return nil
	}
	return fmt.Errorf("%s", privilegeDeniedMessage())
}
