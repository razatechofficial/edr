package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/razatechofficial/edr/internal/controlplane"
	"github.com/razatechofficial/edr/pkg/protocol"
)

func main() {
	grpcAddr := flag.String("grpc-addr", envOr("EDR_CONTROLPLANE_GRPC", ":50051"), "gRPC listen address")
	httpAddr := flag.String("http-addr", envOr("EDR_CONTROLPLANE_HTTP", ":8080"), "HTTP listen address")
	dataDir := flag.String("data-dir", envOr("EDR_CONTROLPLANE_DATA", "./controlplane-data"), "registry and alert storage directory")
	heartbeatSec := flag.Int("heartbeat-sec", 30, "default agent heartbeat interval")
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	registry, err := controlplane.NewRegistry(controlplane.RegistryConfig{
		DataDir:      *dataDir,
		HeartbeatSec: int32(*heartbeatSec),
	})
	if err != nil {
		log.Fatalf("registry: %v", err)
	}

	grpcSvc := controlplane.NewGRPCService(registry, logger)
	grpcServer := grpc.NewServer()
	protocol.RegisterEDRServiceServer(grpcServer, grpcSvc)

	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatalf("grpc listen: %v", err)
	}

	httpSrv := controlplane.NewServer()
	go func() {
		log.Printf("controlplane HTTP listening on %s", *httpAddr)
		if err := http.ListenAndServe(*httpAddr, httpSrv.Routes()); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	go func() {
		log.Printf("controlplane gRPC listening on %s (data dir: %s)", *grpcAddr, *dataDir)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("grpc server: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	grpcServer.GracefulStop()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
