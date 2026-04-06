package telemetry

import (
	"bytes"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	encoderPool sync.Pool
	decoderPool sync.Pool
)

func init() {
	encoderPool = sync.Pool{
		New: func() interface{} {
			enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
			return enc
		},
	}
	decoderPool = sync.Pool{
		New: func() interface{} {
			dec, _ := zstd.NewReader(nil)
			return dec
		},
	}
}

// Compress applies zstd compression to data. Encoders are pooled for reuse
// across concurrent callers.
func Compress(data []byte) ([]byte, error) {
	enc := encoderPool.Get().(*zstd.Encoder)
	defer encoderPool.Put(enc)

	var buf bytes.Buffer
	enc.Reset(&buf)
	if _, err := enc.Write(data); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress restores zstd-compressed data. Decoders are pooled for reuse.
func Decompress(data []byte) ([]byte, error) {
	dec := decoderPool.Get().(*zstd.Decoder)
	defer decoderPool.Put(dec)

	if err := dec.Reset(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return io.ReadAll(dec)
}
