package xdrclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	forensicsv1 "github.com/razatechofficial/xdr/api/proto/forensics/v1"
)

// fakeForensics is a server that behaves the way the real one does: it stages
// bytes at the offset it was given and verifies the digest before declaring the
// bundle stored.
type fakeForensics struct {
	forensicsv1.UnimplementedForensicsServiceServer

	mu       sync.Mutex
	staged   map[string][]byte
	complete map[string]bool
	// failAfter drops the stream once this many chunks have arrived, to stand
	// in for a connection lost mid-upload. Zero means never.
	failAfter int
	// pretendEmpty makes the server behave like a replica that staged nothing:
	// it discards whatever it holds and refuses any non-zero resume offset.
	pretendEmpty bool
	headers      []*forensicsv1.BundleHeader
}

func newFakeForensics() *fakeForensics {
	return &fakeForensics{staged: map[string][]byte{}, complete: map[string]bool{}}
}

func (f *fakeForensics) GetUploadState(_ context.Context, req *forensicsv1.UploadStateRequest) (*forensicsv1.UploadStateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uid := req.GetBundleUid()
	if f.complete[uid] {
		return &forensicsv1.UploadStateResponse{Known: true, Complete: true, BytesStored: int64(len(f.staged[uid]))}, nil
	}
	staged, ok := f.staged[uid]
	if !ok || len(staged) == 0 {
		return &forensicsv1.UploadStateResponse{}, nil
	}
	return &forensicsv1.UploadStateResponse{Known: true, BytesStored: int64(len(staged))}, nil
}

func (f *fakeForensics) UploadBundle(stream forensicsv1.ForensicsService_UploadBundleServer) error {
	var (
		header *forensicsv1.BundleHeader
		offset int64
		chunks int
	)
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch body := frame.GetBody().(type) {
		case *forensicsv1.BundleFrame_Header:
			header = body.Header
			f.mu.Lock()
			f.headers = append(f.headers, header)
			if f.pretendEmpty {
				delete(f.staged, header.GetBundleUid())
			}
			staged := int64(len(f.staged[header.GetBundleUid()]))
			f.mu.Unlock()
			if header.GetResumeFromOffset() != staged {
				return status.Errorf(codes.OutOfRange, "resume from %d", staged)
			}
			offset = header.GetResumeFromOffset()
		case *forensicsv1.BundleFrame_Chunk:
			if header == nil {
				return status.Error(codes.InvalidArgument, "chunk before header")
			}
			if body.Chunk.GetOffset() != offset {
				return status.Errorf(codes.OutOfRange, "resume from %d", offset)
			}
			f.mu.Lock()
			f.staged[header.GetBundleUid()] = append(f.staged[header.GetBundleUid()], body.Chunk.GetData()...)
			f.mu.Unlock()
			offset += int64(len(body.Chunk.GetData()))
			chunks++
			if f.failAfter > 0 && chunks >= f.failAfter {
				return status.Error(codes.Unavailable, "connection lost")
			}
		}
	}
	if header == nil {
		return status.Error(codes.InvalidArgument, "no header")
	}

	f.mu.Lock()
	staged := f.staged[header.GetBundleUid()]
	f.mu.Unlock()
	if int64(len(staged)) < header.GetTotalBytes() {
		return stream.SendAndClose(&forensicsv1.UploadAck{BytesStored: int64(len(staged)), Message: "incomplete"})
	}
	sum := sha256.Sum256(staged)
	if hex.EncodeToString(sum[:]) != header.GetSha256() {
		f.mu.Lock()
		delete(f.staged, header.GetBundleUid())
		f.mu.Unlock()
		return stream.SendAndClose(&forensicsv1.UploadAck{Message: "digest mismatch"})
	}
	f.mu.Lock()
	f.complete[header.GetBundleUid()] = true
	f.mu.Unlock()
	return stream.SendAndClose(&forensicsv1.UploadAck{
		Accepted:       true,
		BytesStored:    int64(len(staged)),
		DigestVerified: true,
		StorageRef:     "s3://test/" + header.GetBundleUid(),
	})
}

// serve starts srv on a loopback port and returns its address.
func serve(t *testing.T, register func(*grpc.Server)) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func writeBundleFile(t *testing.T, size int) (path, digest string) {
	t.Helper()
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	path = filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:])
}

func testClient(addr string) *ForensicsClient {
	return NewForensicsClient([]string{addr}, Store{}, true,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestUploadShipsAndVerifiesABundle(t *testing.T) {
	fake := newFakeForensics()
	addr := serve(t, func(s *grpc.Server) { forensicsv1.RegisterForensicsServiceServer(s, fake) })
	path, digest := writeBundleFile(t, 3*forensicsChunkBytes+17)

	out, err := testClient(addr).Upload(context.Background(), Bundle{
		Path: path, UID: "bundle-1", AlertUID: "alert-1",
		Kind: "artifact_bundle", ContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !out.Stored {
		t.Fatalf("bundle was not stored: %+v", out)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.headers[0].GetSha256() != digest {
		t.Fatalf("header digest %q does not describe the file (%q)", fake.headers[0].GetSha256(), digest)
	}
	if fake.headers[0].GetTotalBytes() != int64(3*forensicsChunkBytes+17) {
		t.Fatalf("header declared %d bytes", fake.headers[0].GetTotalBytes())
	}
}

func TestUploadResumesAfterTheConnectionDrops(t *testing.T) {
	fake := newFakeForensics()
	fake.failAfter = 2
	addr := serve(t, func(s *grpc.Server) { forensicsv1.RegisterForensicsServiceServer(s, fake) })
	path, _ := writeBundleFile(t, 5*forensicsChunkBytes)
	client := testClient(addr)
	bundle := Bundle{Path: path, UID: "bundle-2", Kind: "memory_dump", ContentType: "application/gzip"}

	if _, err := client.Upload(context.Background(), bundle); err == nil {
		t.Fatal("an upload cut off mid-stream was reported as success")
	}
	fake.mu.Lock()
	stagedAfterFailure := len(fake.staged[bundle.UID])
	fake.mu.Unlock()
	if stagedAfterFailure != 2*forensicsChunkBytes {
		t.Fatalf("server staged %d bytes, expected %d", stagedAfterFailure, 2*forensicsChunkBytes)
	}

	// Second attempt: the state query reports the staged offset and only the
	// remainder is sent.
	fake.failAfter = 0
	out, err := client.Upload(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resumed upload: %v", err)
	}
	if !out.Stored {
		t.Fatalf("resumed bundle was not stored: %+v", out)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.headers[1].GetResumeFromOffset(); got != int64(stagedAfterFailure) {
		t.Fatalf("resumed from %d, expected %d", got, stagedAfterFailure)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if string(fake.staged[bundle.UID]) != string(original) {
		t.Fatal("the reassembled bundle is not the file that was sent")
	}
}

func TestUploadRestartsWhenTheServerCannotResume(t *testing.T) {
	fake := newFakeForensics()
	fake.failAfter = 1
	addr := serve(t, func(s *grpc.Server) { forensicsv1.RegisterForensicsServiceServer(s, fake) })
	path, _ := writeBundleFile(t, 3*forensicsChunkBytes)
	client := testClient(addr)
	bundle := Bundle{Path: path, UID: "bundle-3", Kind: "dfir_package", ContentType: "application/zip"}

	if _, err := client.Upload(context.Background(), bundle); err == nil {
		t.Fatal("an interrupted upload was reported as success")
	}

	// The replica that answers next has nothing staged, so it refuses the
	// resume offset the state query produced. The agent must start over rather
	// than abandon the evidence.
	fake.failAfter = 0
	fake.pretendEmpty = true
	out, err := client.Upload(context.Background(), bundle)
	if err != nil {
		t.Fatalf("restarted upload: %v", err)
	}
	if !out.Stored {
		t.Fatalf("restarted bundle was not stored: %+v", out)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	// Three headers: the interrupted attempt, the refused resume, and the
	// restart from zero.
	if len(fake.headers) != 3 {
		t.Fatalf("%d headers were sent, expected 3", len(fake.headers))
	}
	if off := fake.headers[1].GetResumeFromOffset(); off == 0 {
		t.Fatal("the second attempt did not try to resume, so the restart path was not exercised")
	}
	if off := fake.headers[2].GetResumeFromOffset(); off != 0 {
		t.Fatalf("the restart sent offset %d, expected 0", off)
	}
}

func TestUploadStopsWhenTheBundleIsAlreadyStored(t *testing.T) {
	fake := newFakeForensics()
	addr := serve(t, func(s *grpc.Server) { forensicsv1.RegisterForensicsServiceServer(s, fake) })
	path, _ := writeBundleFile(t, 1024)
	client := testClient(addr)
	bundle := Bundle{Path: path, UID: "bundle-4", Kind: "artifact_bundle", ContentType: "application/json"}

	if _, err := client.Upload(context.Background(), bundle); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	fake.mu.Lock()
	headersAfterFirst := len(fake.headers)
	fake.mu.Unlock()

	out, err := client.Upload(context.Background(), bundle)
	if err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if !out.Stored {
		t.Fatalf("a stored bundle was not reported as stored: %+v", out)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.headers) != headersAfterFirst {
		t.Fatal("a bundle the platform already holds was uploaded again")
	}
}

func TestUploadReportsAnUnsupportedPlatformDistinctly(t *testing.T) {
	// A server with no forensics service registered: the agent must stop asking
	// rather than retry an RPC that will never exist.
	addr := serve(t, func(s *grpc.Server) {})
	path, _ := writeBundleFile(t, 512)

	_, err := testClient(addr).Upload(context.Background(), Bundle{
		Path: path, UID: "bundle-5", Kind: "artifact_bundle", ContentType: "application/json",
	})
	if !errors.Is(err, ErrForensicsUnsupported) {
		t.Fatalf("expected ErrForensicsUnsupported, got %v", err)
	}
}

func TestUploadDoesNotClaimStorageOnADigestMismatch(t *testing.T) {
	fake := newFakeForensics()
	addr := serve(t, func(s *grpc.Server) { forensicsv1.RegisterForensicsServiceServer(s, fake) })
	path, _ := writeBundleFile(t, 2048)
	// Rewrite the file after the digest is computed — the file this agent
	// hashes and the file it sends must be the same one, and when they are not
	// the ack must not say "stored".
	client := testClient(addr)
	bundle := Bundle{Path: path, UID: "bundle-6", Kind: "artifact_bundle", ContentType: "application/json"}

	// Prime the server with a different digest for this uid by staging bytes
	// that do not match, then upload: the fake recomputes and refuses.
	fake.mu.Lock()
	fake.staged[bundle.UID] = []byte("not the bundle")
	fake.mu.Unlock()

	out, err := client.Upload(context.Background(), bundle)
	if err == nil && out.Stored {
		t.Fatalf("a bundle the server did not verify was reported as stored: %+v", out)
	}
}

func TestUploadRefusesAMissingFile(t *testing.T) {
	addr := serve(t, func(s *grpc.Server) { forensicsv1.RegisterForensicsServiceServer(s, newFakeForensics()) })
	_, err := testClient(addr).Upload(context.Background(), Bundle{
		Path: filepath.Join(t.TempDir(), "absent.json"), UID: "bundle-7",
		Kind: "artifact_bundle", ContentType: "application/json",
	})
	if err == nil {
		t.Fatal("an upload of a file that does not exist was accepted")
	}
}

func TestUploadRefusesWithNoHostsConfigured(t *testing.T) {
	path, _ := writeBundleFile(t, 16)
	_, err := NewForensicsClient(nil, Store{}, true, slog.New(slog.NewTextHandler(io.Discard, nil))).
		Upload(context.Background(), Bundle{Path: path, UID: "bundle-8", Kind: "artifact_bundle"})
	if err == nil {
		t.Fatal("an upload with no ingest hosts was attempted")
	}
}

func TestHashFileMatchesTheFileContents(t *testing.T) {
	path, digest := writeBundleFile(t, 4096)
	size, got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if size != 4096 {
		t.Fatalf("size %d, expected 4096", size)
	}
	if got != digest {
		t.Fatalf("digest %q, expected %q", got, digest)
	}
}

func TestUploadReportsASpentAllowanceDistinctly(t *testing.T) {
	// A server that refuses on allowance grounds. The agent must be able to
	// tell this from a transient failure, or it will retry every cycle and be
	// refused every time.
	addr := serve(t, func(s *grpc.Server) {
		forensicsv1.RegisterForensicsServiceServer(s, &budgetRefusingForensics{})
	})
	path, _ := writeBundleFile(t, 1024)

	_, err := testClient(addr).Upload(context.Background(), Bundle{
		Path: path, UID: "budget-1", Kind: "artifact_bundle", ContentType: "application/json",
	})
	if !errors.Is(err, ErrForensicsOverBudget) {
		t.Fatalf("expected ErrForensicsOverBudget, got %v", err)
	}
	// Not conflated with an unsupported platform: one clears on its own, the
	// other never does.
	if errors.Is(err, ErrForensicsUnsupported) {
		t.Fatal("a spent allowance was reported as an unsupported platform")
	}
}

// budgetRefusingForensics answers every upload with ResourceExhausted.
type budgetRefusingForensics struct {
	forensicsv1.UnimplementedForensicsServiceServer
}

func (budgetRefusingForensics) GetUploadState(context.Context, *forensicsv1.UploadStateRequest) (*forensicsv1.UploadStateResponse, error) {
	return &forensicsv1.UploadStateResponse{}, nil
}

func (budgetRefusingForensics) UploadBundle(stream forensicsv1.ForensicsService_UploadBundleServer) error {
	return status.Error(codes.ResourceExhausted, "the tenant's daily evidence budget is spent")
}

func TestASpentAllowanceIsNotRetriedAcrossHosts(t *testing.T) {
	// The allowance belongs to the tenant, so trying a second replica would
	// spend bandwidth to be refused again.
	calls := 0
	addr := serve(t, func(s *grpc.Server) {
		forensicsv1.RegisterForensicsServiceServer(s, &countingBudgetRefusal{calls: &calls})
	})
	path, _ := writeBundleFile(t, 512)
	client := NewForensicsClient([]string{addr, addr, addr}, Store{}, true,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := client.Upload(context.Background(), Bundle{
		Path: path, UID: "budget-2", Kind: "artifact_bundle", ContentType: "application/json",
	}); !errors.Is(err, ErrForensicsOverBudget) {
		t.Fatalf("expected ErrForensicsOverBudget, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("the upload was attempted %d times across hosts, expected 1", calls)
	}
}

type countingBudgetRefusal struct {
	forensicsv1.UnimplementedForensicsServiceServer
	calls *int
}

func (c *countingBudgetRefusal) GetUploadState(context.Context, *forensicsv1.UploadStateRequest) (*forensicsv1.UploadStateResponse, error) {
	return &forensicsv1.UploadStateResponse{}, nil
}

func (c *countingBudgetRefusal) UploadBundle(stream forensicsv1.ForensicsService_UploadBundleServer) error {
	*c.calls++
	return status.Error(codes.ResourceExhausted, "spent")
}
