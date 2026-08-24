//go:build windows

package collector

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"github.com/razatechofficial/edr/internal/config"
	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDAll = 5
	mibTcpStateListen    = 2

	maxMIBConnRows = 8192

)

var (
	modiphlpapiWin             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTableWin = modiphlpapiWin.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTableWin = modiphlpapiWin.NewProc("GetExtendedUdpTable")
)

func mibPortFromDWORD(dw uint32) int {
	return int(uint16(dw>>8) | uint16(dw&0xff)<<8)
}

func mibDwordToIPv4(dw uint32) net.IP {
	return net.IPv4(byte(dw), byte(dw>>8), byte(dw>>16), byte(dw>>24))
}

func getExtendedTcpTableAF(af uintptr) ([]byte, error) {
	if err := procGetExtendedTcpTableWin.Find(); err != nil {
		return nil, err
	}
	var size uint32
	r0, _, _ := procGetExtendedTcpTableWin.Call(0, uintptr(unsafe.Pointer(&size)), 1, af, uintptr(tcpTableOwnerPIDAll), 0)
	if errno := uintptrToMIBErr(r0); errno != nil && !errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, errno
	}
	if size == 0 {
		size = 65536
	}
	buf := make([]byte, size)
	r0, _, _ = procGetExtendedTcpTableWin.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, af, uintptr(tcpTableOwnerPIDAll), 0)
	if errno := uintptrToMIBErr(r0); errno != nil {
		if errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) && int(size) > len(buf) {
			buf = make([]byte, size)
			r0, _, _ = procGetExtendedTcpTableWin.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, af, uintptr(tcpTableOwnerPIDAll), 0)
			if errno2 := uintptrToMIBErr(r0); errno2 != nil {
				return nil, errno2
			}
		} else {
			return nil, errno
		}
	}
	if int(size) < len(buf) {
		buf = buf[:size]
	}
	return buf, nil
}

// getExtendedTcp6Buf uses GetExtendedTcpTable(AF_INET6). There is no
// GetExtendedTcp6Table export in iphlpapi.dll; calling a missing LazyProc panics.
func getExtendedTcp6Buf() ([]byte, error) {
	return getExtendedTcpTableAF(uintptr(syscall.AF_INET6))
}

func getExtendedUDPTableAF(af uintptr) ([]byte, error) {
	if err := procGetExtendedUdpTableWin.Find(); err != nil {
		return nil, err
	}
	var size uint32
	r0, _, _ := procGetExtendedUdpTableWin.Call(0, uintptr(unsafe.Pointer(&size)), 1, af, 1, 0)
	if errno := uintptrToMIBErr(r0); errno != nil && !errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, errno
	}
	if size == 0 {
		size = 65536
	}
	buf := make([]byte, size)
	r0, _, _ = procGetExtendedUdpTableWin.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, af, 1, 0)
	if errno := uintptrToMIBErr(r0); errno != nil {
		if errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) && int(size) > len(buf) {
			buf = make([]byte, size)
			r0, _, _ = procGetExtendedUdpTableWin.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, af, 1, 0)
			if errno2 := uintptrToMIBErr(r0); errno2 != nil {
				return nil, errno2
			}
		} else {
			return nil, errno
		}
	}
	if int(size) < len(buf) {
		buf = buf[:size]
	}
	return buf, nil
}

func getExtendedUdp6Buf() ([]byte, error) {
	if err := procGetExtendedUdpTableWin.Find(); err != nil {
		return nil, err
	}
	var size uint32
	r0, _, _ := procGetExtendedUdpTableWin.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(syscall.AF_INET6), 1, 0)
	if errno := uintptrToMIBErr(r0); errno != nil && !errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, errno
	}
	if size == 0 {
		size = 131072
	}
	buf := make([]byte, size)
	r0, _, _ = procGetExtendedUdpTableWin.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(syscall.AF_INET6), 1, 0)
	if errno := uintptrToMIBErr(r0); errno != nil {
		if errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) && int(size) > len(buf) {
			buf = make([]byte, size)
			r0, _, _ = procGetExtendedUdpTableWin.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(syscall.AF_INET6), 1, 0)
			if errno2 := uintptrToMIBErr(r0); errno2 != nil {
				return nil, errno2
			}
		} else {
			return nil, errno
		}
	}
	if int(size) < len(buf) {
		buf = buf[:size]
	}
	return buf, nil
}

func uintptrToMIBErr(r uintptr) error {
	switch r {
	case 0:
		return nil
	default:
		return syscall.Errno(r)
	}
}

// windowsMIBTCPConnections returns non-LISTEN TCP rows from IPv4 + IPv6 tables (PID-qualified).
func windowsMIBTCPConnections(limit int) ([]connEntry, error) {
	out := make([]connEntry, 0, limit)
	v4e := func(rows []connEntry) {
		for _, r := range rows {
			if len(out) >= limit {
				return
			}
			out = append(out, r)
		}
	}

	buf4, err := getExtendedTcpTableAF(uintptr(syscall.AF_INET))
	if err != nil {
		return nil, err
	}
	rows4, err := mibTCPConnRowsIPv4(buf4, limit-len(out))
	if err != nil {
		return nil, err
	}
	v4e(rows4)

	if len(out) >= limit {
		return out, nil
	}

	buf6, err := getExtendedTcp6Buf()
	if err != nil {
		return out, nil // IPv4-only fallback
	}
	rows6, err := mibTCPConnRowsIPv6(buf6, limit-len(out))
	if err != nil {
		return out, nil
	}
	v4e(rows6)

	// UDP coverage (owner-PID rows)
	if len(out) < limit {
		if ub4, err := getExtendedUDPTableAF(uintptr(syscall.AF_INET)); err == nil {
			rowsu4, _ := mibUDPConnRowsIPv4(ub4, limit-len(out))
			v4e(rowsu4)
		}
	}
	if len(out) < limit {
		if ub6, err := getExtendedUdp6Buf(); err == nil {
			rowsu6, _ := mibUDPConnRowsIPv6(ub6, limit-len(out))
			v4e(rowsu6)
		}
	}
	return out, nil
}

func mibTCPConnRowsIPv4(buf []byte, lim int) ([]connEntry, error) {
	const rowSize = 24
	out := make([]connEntry, 0, lim)
	if len(buf) < 4 {
		return out, nil
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	for i := uint32(0); i < num && len(out) < lim; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		off += rowSize

		state := binary.LittleEndian.Uint32(row[0:4])
		if state == mibTcpStateListen {
			continue
		}

		lp := mibPortFromDWORD(binary.LittleEndian.Uint32(row[8:12]))
		rp := mibPortFromDWORD(binary.LittleEndian.Uint32(row[16:20]))
		out = append(out, connEntry{
			proto: "tcp",
			srcIP:   mibDwordToIPv4(binary.LittleEndian.Uint32(row[4:8])).String(),
			srcPort: lp,
			dstIP:   mibDwordToIPv4(binary.LittleEndian.Uint32(row[12:16])).String(),
			dstPort: rp,
			pid: int(binary.LittleEndian.Uint32(row[20:24])),
		})
	}
	return out, nil
}

func mibTCPConnRowsIPv6(buf []byte, lim int) ([]connEntry, error) {
	const rowSize = 56
	out := make([]connEntry, 0, lim)
	if len(buf) < 4 {
		return out, nil
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	for i := uint32(0); i < num && len(out) < lim; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		off += rowSize

		if binary.LittleEndian.Uint32(row[48:52]) == mibTcpStateListen {
			continue
		}

		lp := mibPortFromDWORD(binary.LittleEndian.Uint32(row[36:40]))
		rp := mibPortFromDWORD(binary.LittleEndian.Uint32(row[44:48]))
		lip := append(net.IP(nil), row[0:16]...)
		rip := append(net.IP(nil), row[16:32]...)
		out = append(out, connEntry{
			proto: "tcp",
			srcIP:   lip.String(),
			srcPort: lp,
			dstIP:   rip.String(),
			dstPort: rp,
			pid: int(binary.LittleEndian.Uint32(row[52:56])),
		})
	}
	return out, nil
}

func mibUDPConnRowsIPv4(buf []byte, lim int) ([]connEntry, error) {
	const rowSize = 12
	out := make([]connEntry, 0, lim)
	if len(buf) < 4 {
		return out, nil
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	for i := uint32(0); i < num && len(out) < lim; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		off += rowSize
		lp := mibPortFromDWORD(binary.LittleEndian.Uint32(row[4:8]))
		out = append(out, connEntry{
			proto:   "udp",
			srcIP:   mibDwordToIPv4(binary.LittleEndian.Uint32(row[0:4])).String(),
			srcPort: lp,
			dstIP:   "0.0.0.0",
			dstPort: 0,
			pid:     int(binary.LittleEndian.Uint32(row[8:12])),
		})
	}
	return out, nil
}

func mibUDPConnRowsIPv6(buf []byte, lim int) ([]connEntry, error) {
	const rowSize = 28
	out := make([]connEntry, 0, lim)
	if len(buf) < 4 {
		return out, nil
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	for i := uint32(0); i < num && len(out) < lim; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		off += rowSize
		lp := mibPortFromDWORD(binary.LittleEndian.Uint32(row[20:24]))
		lip := append(net.IP(nil), row[0:16]...)
		out = append(out, connEntry{
			proto:   "udp",
			srcIP:   lip.String(),
			srcPort: lp,
			dstIP:   "::",
			dstPort: 0,
			pid:     int(binary.LittleEndian.Uint32(row[24:28])),
		})
	}
	return out, nil
}

// windowsListenMIBRowCounts returns MIB-derived TCP listener totals and PID-qualified listener rows (IPv4+IPv6).
func windowsListenMIBRowCounts() (listenerRows int, pidOwning int) {
	b4, err := getExtendedTcpTableAF(uintptr(syscall.AF_INET))
	if err != nil {
		return 0, 0
	}
	t4, o4 := countListenRowsIPv4(b4)

	b6, err := getExtendedTcp6Buf()
	if err != nil {
		return t4, o4
	}
	t6, o6 := countListenRowsIPv6(b6)
	return t4 + t6, o4 + o6
}

func countListenRowsIPv4(buf []byte) (total int, owning int) {
	const rowSize = 24
	if len(buf) < 4 {
		return 0, 0
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	for i := uint32(0); i < num; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		off += rowSize
		if binary.LittleEndian.Uint32(row[0:4]) != mibTcpStateListen {
			continue
		}
		total++
		if binary.LittleEndian.Uint32(row[20:24]) != 0 {
			owning++
		}
	}
	return total, owning
}

func countListenRowsIPv6(buf []byte) (total int, owning int) {
	const rowSize = 56
	if len(buf) < 4 {
		return 0, 0
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	for i := uint32(0); i < num; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		off += rowSize
		if binary.LittleEndian.Uint32(row[48:52]) != mibTcpStateListen {
			continue
		}
		total++
		if binary.LittleEndian.Uint32(row[52:56]) != 0 {
			owning++
		}
	}
	return total, owning
}

func inventoryListenerAttributionMIB(listenerRows int, pidHints int) string {
	if listenerRows == 0 {
		return "unavailable"
	}
	if pidHints >= listenerRows {
		return "full"
	}
	if pidHints > 0 {
		return "partial"
	}
	return "count_only"
}

func (nc *NetworkCollector) windowsShouldPollUserlandNet() (poll bool, policy string) {
	if nc == nil {
		return true, ""
	}
	s := strings.ToLower(strings.TrimSpace(nc.cfg.Monitoring.WindowsUserlandNetTable))

	elev := isNetWindowsElevated()
	wantK := WantKernelTier(nc.cfg)
	switch s {
	case "off":
		return false, "off"
	case "on":
		return true, "on"
	case "force":
		return true, "force"
	default:
		_ = elev
		_ = wantK
		return true, "auto"
	}
}

// WindowsUserlandNetPolicyDesc is exported for tests / doctor (optional helper).
func WindowsUserlandNetPolicyDesc(cfg config.Config) string {
	s := strings.ToLower(strings.TrimSpace(cfg.Monitoring.WindowsUserlandNetTable))
	if s != "" && s != "auto" && s != "on" && s != "off" && s != "force" {
		return "invalid_windows_userland_net_table"
	}
	nc := NetworkCollector{cfg: cfg}
	on, tag := nc.windowsShouldPollUserlandNet()
	if on {
		return "polling:" + tag
	}
	return "delegated:" + tag
}
