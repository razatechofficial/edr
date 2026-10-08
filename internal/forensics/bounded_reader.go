package forensics

import "io"

// boundedReader stops after n bytes.
//
// io.LimitReader would do, but it reports the limit as a clean EOF, which a
// JSON decoder reads as a truncated document rather than as "this file is not
// what we expected". Keeping it explicit makes the distinction available.
type boundedReader struct {
	r         io.Reader
	remaining int64
}

func newBoundedReader(r io.Reader, limit int64) io.Reader {
	return &boundedReader{r: r, remaining: limit}
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}
