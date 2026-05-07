//go:build darwin

package networkext

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

type SocketReader struct {
	Path string
}

func (s *SocketReader) ReadFrames(ctx context.Context, onFrame func(map[string]any)) error {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "unix", s.Path)
	if err != nil {
		return err
	}
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var n uint32
		if err := binary.Read(br, binary.LittleEndian, &n); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if n == 0 || n > 1<<20 {
			return fmt.Errorf("invalid frame length %d", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(buf, &m); err != nil {
			continue
		}
		if onFrame != nil {
			onFrame(m)
		}
	}
}

