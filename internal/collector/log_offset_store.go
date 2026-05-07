package collector

import "encoding/json"

// persistedLogOffset tracks byte offset plus optional st_dev/st_ino so log rotation
// (rename + new inode) resets tailing to the start of the new file.
type persistedLogOffset struct {
	Dev uint64 `json:"dev,omitempty"`
	Ino uint64 `json:"ino,omitempty"`
	Off int64  `json:"off"`
}

func loadPersistedLogOffsets(data []byte) map[string]persistedLogOffset {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || len(raw) == 0 {
		return nil
	}
	out := make(map[string]persistedLogOffset, len(raw))
	for k, v := range raw {
		var n float64
		if json.Unmarshal(v, &n) == nil {
			out[k] = persistedLogOffset{Off: int64(n)}
			continue
		}
		var p persistedLogOffset
		if json.Unmarshal(v, &p) == nil {
			out[k] = p
		}
	}
	return out
}

func pickLogReadOffset(pos persistedLogOffset, fiDev, fiIno uint64, fiSize int64) int64 {
	off := pos.Off
	if pos.Dev != 0 && pos.Ino != 0 && fiDev != 0 && fiIno != 0 {
		if pos.Dev != fiDev || pos.Ino != fiIno {
			return 0
		}
	}
	if off > fiSize {
		return 0
	}
	return off
}
