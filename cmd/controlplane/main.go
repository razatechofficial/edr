package main

import (
	"log"
	"net/http"

	"github.com/razatechofficial/edr/internal/controlplane"
)

func main() {
	srv := controlplane.NewServer()
	log.Println("controlplane listening on :8080")
	if err := http.ListenAndServe(":8080", srv.Routes()); err != nil {
		log.Fatalf("controlplane failed: %v", err)
	}
}
