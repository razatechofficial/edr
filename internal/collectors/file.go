package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"os"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// FileOpenEvent is emitted when a file is opened.
type FileOpenEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Path      string    `json:"path"`
	Flags     uint32    `json:"flags"`
}

// FileWriteEvent is emitted when data is written to a file.
// Entropy is the Shannon entropy of the written content, useful
// for ransomware detection (encrypted data ≈ 8.0 bits/byte).
type FileWriteEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	PID          uint32    `json:"pid"`
	Path         string    `json:"path"`
	BytesWritten uint64    `json:"bytes_written"`
	Entropy      float64   `json:"entropy"`
}

// FileDeleteEvent is emitted when a file is deleted.
type FileDeleteEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256,omitempty"`
}

// FileRenameEvent is emitted when a file is renamed or moved.
type FileRenameEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	OldPath   string    `json:"old_path"`
	NewPath   string    `json:"new_path"`
}

// FileCreateEvent is emitted when a new file is created.
type FileCreateEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256,omitempty"`
}

// FileCollector handles file system operation events, computing
// content entropy for write events and file hashes for creates and deletes.
type FileCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
}

// NewFileCollector creates a FileCollector with the given logger.
func NewFileCollector(logger *zap.Logger) *FileCollector {
	return &FileCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *FileCollector) Name() string { return "file" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *FileCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventFile}
}

// Start stores the output channel.
func (c *FileCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op.
func (c *FileCollector) Stop() error { return nil }

func (c *FileCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventFileOpen:
		c.handleOpen(evt)
	case EventFileWrite:
		c.handleWrite(evt)
	case EventFileDelete:
		c.handleDelete(evt)
	case EventFileRename:
		c.handleRename(evt)
	case EventFileCreate:
		c.handleCreate(evt)
	}
}

func (c *FileCollector) handleOpen(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	path := r.String()
	flags := r.Uint32()
	if r.Err() != nil {
		c.logger.Warn("malformed file open payload", zap.Error(r.Err()))
		return
	}

	c.emit(&FileOpenEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Path:      path,
		Flags:     flags,
	})
}

func (c *FileCollector) handleWrite(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	path := r.String()
	bytesWritten := r.Uint64()
	contentLen := r.Uint32()
	content := r.Bytes(int(contentLen))
	if r.Err() != nil {
		c.logger.Warn("malformed file write payload", zap.Error(r.Err()))
		return
	}

	c.emit(&FileWriteEvent{
		Timestamp:    evt.Timestamp,
		PID:          evt.PID,
		Path:         path,
		BytesWritten: bytesWritten,
		Entropy:      shannonEntropy(content),
	})
}

func (c *FileCollector) handleDelete(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	path := r.String()
	if r.Err() != nil {
		c.logger.Warn("malformed file delete payload", zap.Error(r.Err()))
		return
	}

	c.emit(&FileDeleteEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Path:      path,
		SHA256:    tryHashFile(path),
	})
}

func (c *FileCollector) handleRename(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	oldPath := r.String()
	newPath := r.String()
	if r.Err() != nil {
		c.logger.Warn("malformed file rename payload", zap.Error(r.Err()))
		return
	}

	c.emit(&FileRenameEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		OldPath:   oldPath,
		NewPath:   newPath,
	})
}

func (c *FileCollector) handleCreate(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	path := r.String()
	if r.Err() != nil {
		c.logger.Warn("malformed file create payload", zap.Error(r.Err()))
		return
	}

	c.emit(&FileCreateEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Path:      path,
		SHA256:    tryHashFile(path),
	})
}

func (c *FileCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping file event")
	}
}

// tryHashFile computes the SHA-256 of the file at path, returning ""
// on any error or if the file exceeds maxHashFileSize.
func tryHashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() > maxHashFileSize {
		return ""
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// shannonEntropy computes the Shannon entropy (bits per byte) of data.
// Fully random data approaches 8.0; constant data returns 0.0.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
