package xdrclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	forensicsv1 "github.com/razatechofficial/xdr/api/proto/forensics/v1"
)

// forensicsChunkBytes is the payload carried in one frame.
//
// Well under gRPC's four-megabyte default so the frame overhead never pushes a
// chunk over the limit, and large enough that a hundred-megabyte dump is a
// hundred round trips rather than a hundred thousand.
const forensicsChunkBytes = 1 << 20

// ErrForensicsUnsupported means the platform this agent is enrolled with does
// not accept evidence uploads.
//
// Distinguished from a transient failure on purpose: an agent that cannot tell
// the two apart would retry forever against a server that will never accept,
// burning the endpoint's bandwidth and filling its own logs.
var ErrForensicsUnsupported = errors.New("xdrclient: the platform does not accept forensic uploads")

// Bundle is a local evidence file to be shipped.
type Bundle struct {
	// Path is the file on this endpoint.
	Path string
	// UID identifies this evidence across retries, and must stay the same for a
	// given collection: that is what makes a resumed upload the same upload
	// rather than a second copy in storage.
	UID         string
	AlertUID    string
	RuleUID     string
	Kind        string
	ContentType string
	CollectedAt time.Time
}

// UploadOutcome is what the platform reported.
type UploadOutcome struct {
	// Stored is true only when the platform accepted the bundle and verified
	// its digest. The local copy must not be deleted on anything less.
	Stored      bool
	BytesStored int64
	StorageRef  string
	Message     string
}

// ForensicsClient uploads evidence bundles to the platform.
//
// A separate connection from the telemetry stream, dialled per upload and
// closed afterwards. Sharing the telemetry connection would put a multi-megabyte
// dump in front of the frames that carry response commands to this endpoint —
// including the one that lifts an isolation.
type ForensicsClient struct {
	hosts    []string
	store    Store
	insecure bool
	log      *slog.Logger
}

// NewForensicsClient builds a client over the same hosts and the same enrolled
// identity as the telemetry stream.
func NewForensicsClient(hosts []string, store Store, insecureSkip bool, log *slog.Logger) *ForensicsClient {
	if log == nil {
		log = slog.Default()
	}
	return &ForensicsClient{
		hosts:    append([]string(nil), hosts...),
		store:    store,
		insecure: insecureSkip,
		log:      log,
	}
}

// Upload ships one bundle, resuming where the platform left off.
//
// Every host is tried before the attempt is reported as failed, because a
// bundle is collected once and the window to ship it closes when the endpoint
// is rebuilt.
func (c *ForensicsClient) Upload(ctx context.Context, b Bundle) (UploadOutcome, error) {
	if c == nil || len(c.hosts) == 0 {
		return UploadOutcome{}, fmt.Errorf("xdrclient: no ingest hosts configured for forensic upload")
	}
	size, digest, err := hashFile(b.Path)
	if err != nil {
		return UploadOutcome{}, err
	}

	var lastErr error
	for _, host := range c.hosts {
		out, err := c.uploadTo(ctx, host, b, size, digest)
		if err == nil {
			return out, nil
		}
		if errors.Is(err, ErrForensicsUnsupported) {
			// Not host-specific: every replica serves the same build.
			return UploadOutcome{}, err
		}
		if ctx.Err() != nil {
			return UploadOutcome{}, ctx.Err()
		}
		c.log.Warn("forensic upload attempt failed",
			"host", host, "bundle_uid", b.UID, "error", err)
		lastErr = err
	}
	return UploadOutcome{}, lastErr
}

func (c *ForensicsClient) uploadTo(ctx context.Context, host string, b Bundle, size int64, digest string) (UploadOutcome, error) {
	conn, err := c.dial(host)
	if err != nil {
		return UploadOutcome{}, err
	}
	defer func() { _ = conn.Close() }()
	client := forensicsv1.NewForensicsServiceClient(conn)

	// Ask first. The platform may already hold this bundle — a previous attempt
	// that was acknowledged after the connection dropped looks identical from
	// here to one that never arrived.
	resumeFrom := int64(0)
	state, err := client.GetUploadState(ctx, &forensicsv1.UploadStateRequest{BundleUid: b.UID})
	switch {
	case err == nil:
		if state.GetComplete() {
			return UploadOutcome{
				Stored:      true,
				BytesStored: state.GetBytesStored(),
				Message:     "already stored",
			}, nil
		}
		if state.GetKnown() && state.GetBytesStored() > 0 && state.GetBytesStored() < size {
			resumeFrom = state.GetBytesStored()
		}
	case status.Code(err) == codes.Unimplemented:
		return UploadOutcome{}, ErrForensicsUnsupported
	default:
		// A failed state query is not a reason to skip the upload; it only
		// means the whole bundle is sent rather than the remainder.
		c.log.Debug("forensic upload state query failed; sending from the start",
			"bundle_uid", b.UID, "error", err)
	}

	out, err := c.send(ctx, client, b, size, digest, resumeFrom)
	if err != nil && status.Code(err) == codes.OutOfRange && resumeFrom > 0 {
		// The platform is not where the state query said it was — most likely
		// the retry reached a different replica. One retry from the beginning,
		// rather than abandoning evidence over a stale offset.
		c.log.Info("forensic upload could not resume; restarting from the beginning",
			"bundle_uid", b.UID, "requested_offset", resumeFrom)
		return c.send(ctx, client, b, size, digest, 0)
	}
	return out, err
}

func (c *ForensicsClient) send(ctx context.Context, client forensicsv1.ForensicsServiceClient, b Bundle, size int64, digest string, from int64) (UploadOutcome, error) {
	f, err := os.Open(b.Path)
	if err != nil {
		return UploadOutcome{}, fmt.Errorf("xdrclient: open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()
	if from > 0 {
		if _, err := f.Seek(from, io.SeekStart); err != nil {
			return UploadOutcome{}, fmt.Errorf("xdrclient: seek bundle to %d: %w", from, err)
		}
	}

	stream, err := client.UploadBundle(ctx)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return UploadOutcome{}, ErrForensicsUnsupported
		}
		return UploadOutcome{}, err
	}

	collected := b.CollectedAt
	if collected.IsZero() {
		collected = time.Now().UTC()
	}
	header := &forensicsv1.BundleHeader{
		BundleUid:        b.UID,
		AlertUid:         b.AlertUID,
		RuleUid:          b.RuleUID,
		Kind:             b.Kind,
		ContentType:      b.ContentType,
		TotalBytes:       size,
		Sha256:           digest,
		CollectedAt:      timestamppb.New(collected.UTC()),
		ResumeFromOffset: from,
	}
	if err := stream.Send(&forensicsv1.BundleFrame{
		Body: &forensicsv1.BundleFrame_Header{Header: header},
	}); err != nil {
		return UploadOutcome{}, uploadSendErr(stream, err)
	}

	buf := make([]byte, forensicsChunkBytes)
	offset := from
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := stream.Send(&forensicsv1.BundleFrame{
				Body: &forensicsv1.BundleFrame_Chunk{Chunk: &forensicsv1.BundleChunk{
					Data:   buf[:n],
					Offset: offset,
				}},
			}); err != nil {
				return UploadOutcome{}, uploadSendErr(stream, err)
			}
			offset += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// The stream is abandoned rather than closed cleanly: closing would
			// ask the platform to finish a bundle this agent knows is short.
			_ = stream.CloseSend()
			return UploadOutcome{}, fmt.Errorf("xdrclient: read bundle: %w", rerr)
		}
		if ctx.Err() != nil {
			_ = stream.CloseSend()
			return UploadOutcome{}, ctx.Err()
		}
	}

	ack, err := stream.CloseAndRecv()
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return UploadOutcome{}, ErrForensicsUnsupported
		}
		return UploadOutcome{}, err
	}
	return UploadOutcome{
		// Both flags are required. "Accepted" alone can mean the bytes arrived
		// and failed verification, and deleting the local copy on that would
		// destroy the only intact evidence.
		Stored:      ack.GetAccepted() && ack.GetDigestVerified(),
		BytesStored: ack.GetBytesStored(),
		StorageRef:  ack.GetStorageRef(),
		Message:     ack.GetMessage(),
	}, nil
}

// uploadSendErr turns a send failure into the server's reason for it.
//
// A gRPC Send reports a broken stream as io.EOF and keeps the real status for
// Recv, so reporting the Send error alone would log "EOF" for every refusal the
// server took the trouble to explain.
func uploadSendErr(stream forensicsv1.ForensicsService_UploadBundleClient, sendErr error) error {
	if _, err := stream.CloseAndRecv(); err != nil {
		return err
	}
	return sendErr
}

func (c *ForensicsClient) dial(host string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if c.insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		c.log.Warn("forensic upload using insecure transport; the endpoint presents no certificate", "host", host)
	} else {
		tlsCfg, err := LoadClientTLSFromStore(c.store)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(TLSConfigForIngestHost(tlsCfg, host))))
	}
	// The send limit is raised because a chunk frame is a megabyte by design.
	// The receive limit stays at the default: the only thing coming back is an
	// acknowledgement.
	opts = append(opts, grpc.WithDefaultCallOptions(
		grpc.MaxCallSendMsgSize(forensicsChunkBytes+(1<<20)),
	))
	return grpc.NewClient(host, opts...)
}

// hashFile returns the size and SHA-256 of a file, streaming it so a memory
// dump is never read into memory to be hashed.
func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("xdrclient: open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return 0, "", fmt.Errorf("xdrclient: stat bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, "", fmt.Errorf("xdrclient: %q is not a regular file", path)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return 0, "", fmt.Errorf("xdrclient: hash bundle: %w", err)
	}
	return info.Size(), hex.EncodeToString(sum.Sum(nil)), nil
}
