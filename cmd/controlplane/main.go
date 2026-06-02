package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/razatechofficial/edr/internal/controlplane"
	"github.com/razatechofficial/edr/pkg/protocol"
)

func main() {
	grpcAddr := flag.String("grpc-addr", envOr("EDR_CONTROLPLANE_GRPC", ":50051"), "gRPC listen address")
	httpAddr := flag.String("http-addr", envOr("EDR_CONTROLPLANE_HTTP", ":8080"), "HTTP listen address")
	dataDir := flag.String("data-dir", envOr("EDR_CONTROLPLANE_DATA", "./controlplane-data"), "registry and alert storage directory")
	heartbeatSec := flag.Int("heartbeat-sec", 30, "default agent heartbeat interval")
	tlsCert := flag.String("tls-cert", envOr("EDR_CONTROLPLANE_TLS_CERT", ""), "server TLS certificate (PEM)")
	tlsKey := flag.String("tls-key", envOr("EDR_CONTROLPLANE_TLS_KEY", ""), "server TLS private key (PEM)")
	tlsClientCA := flag.String("tls-client-ca", envOr("EDR_CONTROLPLANE_TLS_CLIENT_CA", ""), "client CA for mutual TLS (PEM)")
	mutualTLS := flag.Bool("mutual-tls", envBool("EDR_CONTROLPLANE_MUTUAL_TLS", false), "require agent client certificates")
	policyDir := flag.String("policy-dir", envOr("EDR_CONTROLPLANE_POLICY_DIR", ""), "rule bundle policy directory (default: <data-dir>/policy)")
	apiToken := flag.String("api-token", envOr("EDR_CONTROLPLANE_API_TOKEN", ""), "optional bearer token for HTTP admin routes")
	flag.Parse()

	policyPath := *policyDir
	if policyPath == "" {
		policyPath = filepath.Join(*dataDir, "policy")
	}

	logger, err := zap.NewProduction(zap.WithCaller(false))
	if err != nil {
		log.Fatalf("logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	tlsCfg, err := controlplane.LoadServerTLS(controlplane.ServerTLSConfig{
		CertPath:     *tlsCert,
		KeyPath:      *tlsKey,
		ClientCAPath: *tlsClientCA,
		MutualTLS:    *mutualTLS,
	})
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	registry, err := controlplane.NewRegistry(controlplane.RegistryConfig{
		DataDir:      *dataDir,
		HeartbeatSec: int32(*heartbeatSec),
	})
	if err != nil {
		log.Fatalf("registry: %v", err)
	}

	policyStore, err := controlplane.NewPolicyStore(policyPath)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}
	if policyStore.PolicyHash() != "" {
		log.Printf("controlplane policy loaded: hash=%s dir=%s", policyStore.PolicyHash(), policyPath)
	}

	grpcSvc := controlplane.NewGRPCService(registry, policyStore, logger)
	var grpcOpts []grpc.ServerOption
	if tlsCfg != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	protocol.RegisterEDRServiceServer(grpcServer, grpcSvc)

	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatalf("grpc listen: %v", err)
	}

	httpSrv := controlplane.NewServerWithRegistry(registry, policyStore)
	go func() {
		handler := httpSrv.RoutesWithAuth(*apiToken)
		if tlsCfg != nil {
			log.Printf("controlplane HTTPS listening on %s (mutual_tls=%v)", *httpAddr, *mutualTLS)
			srv := &http.Server{
				Addr:      *httpAddr,
				Handler:   handler,
				TLSConfig: tlsCfg.Clone(),
			}
			if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
				log.Fatalf("https server: %v", err)
			}
			return
		}
		log.Printf("controlplane HTTP listening on %s", *httpAddr)
		if err := http.ListenAndServe(*httpAddr, handler); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	go func() {
		mode := "plaintext"
		if tlsCfg != nil {
			mode = "tls"
		}
		log.Printf("controlplane gRPC listening on %s (%s, data dir: %s)", *grpcAddr, mode, *dataDir)
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

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}
