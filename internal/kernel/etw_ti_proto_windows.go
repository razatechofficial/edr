//go:build windows

package kernel

import (
	"encoding/binary"
	"fmt"
)

func encodeTIEvent(ev TIEvent) []byte {
	b := make([]byte, 36)
	b[0] = ev.Opcode
	binary.LittleEndian.PutUint32(b[4:8], ev.CallerPID)
	binary.LittleEndian.PutUint32(b[8:12], ev.TargetPID)
	binary.LittleEndian.PutUint64(b[12:20], ev.BaseAddress)
	binary.LittleEndian.PutUint64(b[20:28], ev.RegionSize)
	binary.LittleEndian.PutUint32(b[28:32], ev.Protect)
	binary.LittleEndian.PutUint32(b[32:36], ev.ThreadID)
	return b
}

func decodeTIEventFrame(b []byte) (TIEvent, error) {
	if len(b) < 36 {
		return TIEvent{}, fmt.Errorf("short ti frame: %d", len(b))
	}
	return TIEvent{
		Opcode:      b[0],
		CallerPID:   binary.LittleEndian.Uint32(b[4:8]),
		TargetPID:   binary.LittleEndian.Uint32(b[8:12]),
		BaseAddress: binary.LittleEndian.Uint64(b[12:20]),
		RegionSize:  binary.LittleEndian.Uint64(b[20:28]),
		Protect:     binary.LittleEndian.Uint32(b[28:32]),
		ThreadID:    binary.LittleEndian.Uint32(b[32:36]),
	}, nil
}
