// Command e2e-xdr-edr exercises: admin CreateToken → EDR Register → ingest StreamTelemetry.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/xdrclient"
	enrollmentv1 "github.com/razatechofficial/xdr/api/proto/enrollment/v1"
)

func main() {
	enrollmentAddr := env("ENROLLMENT_ADDR", "127.0.0.1:50051")
	adminKey := env("ADMIN_KEY", "e2e-admin-key")
	tenantID := env("TENANT_ID", "550e8400-e29b-41d4-a716-446655440001")
	orgID := env("ORG_ID", "550e8400-e29b-41d4-a716-446655440002")
	userID := env("USER_ID", "550e8400-e29b-41d4-a716-446655440003")
	dataDir := env("DATA_DIR", filepath.Join(os.TempDir(), "edr-xdr-e2e"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log.Printf("connecting enrollment admin at %s", enrollmentAddr)
	conn, err := grpc.NewClient(enrollmentAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial enrollment: %v", err)
	}
	defer conn.Close()

	admin := enrollmentv1.NewEnrollmentAdminServiceClient(conn)
	adminCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"x-enrollment-admin-key", adminKey,
		"x-tenant-id", tenantID,
		"x-user-id", userID,
		"x-org-id", orgID,
	))
	tok, err := admin.CreateToken(adminCtx, &enrollmentv1.CreateTokenRequest{
		Label:   "edr-e2e",
		MaxUses: 1,
	})
	if err != nil {
		log.Fatalf("create token: %v", err)
	}
	log.Printf("created enrollment token id=%s", tok.GetTokenId())

	agentID := uuid.NewString()
	_ = os.MkdirAll(dataDir, 0o700)
	_ = os.WriteFile(filepath.Join(dataDir, "agent_id"), []byte(agentID+"\n"), 0o600)

	enrollRes, err := xdrclient.EnsureEnrolled(ctx, xdrclient.EnrollOptions{
		Config: config.XDRConfig{
			Enabled:         true,
			EnrollmentHost:  enrollmentAddr,
			EnrollmentToken: tok.GetEnrollmentToken(),
			CertDir:         filepath.Join(dataDir, "xdr-tls"),
			InsecureSkipTLS: true,
			RenewBeforeDays: 7,
		},
		AgentID:  agentID,
		AgentVer: "e2e-1.0.0",
		DataDir:  dataDir,
	})
	if err != nil {
		log.Fatalf("edr enroll: %v", err)
	}
	log.Printf("enrolled agent_id=%s ingest_hosts=%v cert_not_after=%s",
		enrollRes.State.AgentID, enrollRes.State.IngestHosts, enrollRes.State.CertNotAfter)

	ingest := xdrclient.NewIngestClient(
		enrollRes.State.IngestHosts,
		enrollRes.State.AgentID,
		enrollRes.Store,
		true, // local ingest TLS off
		enrollRes.State.HeartbeatSec,
		nil,
	)
	defer ingest.Close()

	payload := []byte(`{"class_uid":1007,"activity_id":1,"severity":{"status":"Success"},"metadata":{"product":{"name":"edr-e2e"},"version":"1.3.0"},"time":` + fmt.Sprintf("%d", time.Now().UnixMilli()) + `}`)
	for i := 0; i < 3; i++ {
		if err := ingest.Send(ctx, payload); err != nil {
			log.Fatalf("ingest send #%d: %v", i+1, err)
		}
		log.Printf("ingest batch #%d ACKed", i+1)
		time.Sleep(200 * time.Millisecond)
	}

	// Confirm agent listed via admin
	agents, err := admin.ListAgents(adminCtx, &enrollmentv1.ListAgentsRequest{})
	if err != nil {
		log.Fatalf("list agents: %v", err)
	}
	found := false
	for _, a := range agents.GetAgents() {
		if a.GetAgentId() == agentID {
			found = true
			log.Printf("agent visible via admin: status=%s hostname=%s", a.GetStatus(), a.GetHostname())
		}
	}
	if !found {
		log.Fatalf("enrolled agent %s not listed by admin", agentID)
	}

	log.Printf("E2E OK — enroll + 3 telemetry batches + admin list")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
