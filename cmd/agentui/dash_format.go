package main

import (
	"fmt"
	"strconv"
	"strings"
)

func formatCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return trimFloat(float64(n)/1_000_000, "M")
	case n >= 1000:
		return trimFloat(float64(n)/1000, "k")
	default:
		return strconv.FormatUint(n, 10)
	}
}

func trimFloat(v float64, suffix string) string {
	if v >= 100 {
		return fmt.Sprintf("%.0f%s", v, suffix)
	}
	s := fmt.Sprintf("%.1f%s", v, suffix)
	return strings.Replace(s, ".0"+suffix, suffix, 1)
}

func compactAgentID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "—"
	}
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func ramHint(used, total uint64) string {
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f / %.0f GB", float64(used)/float64(1<<30), float64(total)/float64(1<<30))
}

func formatMemShort(bytes uint64) string {
	mb := float64(bytes) / (1024 * 1024)
	if mb < 1024 {
		if mb < 10 {
			return fmt.Sprintf("%.1f MB", mb)
		}
		return fmt.Sprintf("%.0f MB", mb)
	}
	gb := mb / 1024
	if gb < 10 {
		return fmt.Sprintf("%.1f GB", gb)
	}
	return fmt.Sprintf("%.0f GB", gb)
}

func formatAgentRAM(mb float64) (value, unit string) {
	if mb < 0 {
		mb = 0
	}
	if mb < 1024 {
		if mb < 10 {
			return fmt.Sprintf("%.1f", mb), "MB"
		}
		return fmt.Sprintf("%.0f", mb), "MB"
	}
	return fmt.Sprintf("%.1f", mb/1024), "GB"
}

func ramBreakdown(res resourceSnapshot) string {
	if res.SysMemTot == 0 {
		return "—"
	}
	return "other " + formatMemShort(res.OtherMem) + " · total " + formatMemShort(res.SysMemTot)
}

func cpuBreakdown(res resourceSnapshot) string {
	return fmt.Sprintf("other %.0f%% · system %.0f%%", res.OtherCPU, res.SysCPU)
}

func rulesLine(uptime string, rules int) string {
	up := dash(uptime)
	if rules > 0 {
		return up + " · Rules " + strconv.Itoa(rules)
	}
	return up + " · Rules —"
}

// clampPos keeps a top-left origin window inside a work area.
func clampPos(x, y, winW, winH, vaX, vaY, vaW, vaH, margin int) (int, int) {
	if winW+2*margin > vaW {
		x = vaX
	} else {
		if x < vaX+margin {
			x = vaX + margin
		}
		if x+winW > vaX+vaW-margin {
			x = vaX + vaW - winW - margin
		}
	}
	if winH+2*margin > vaH {
		y = vaY
	} else {
		if y < vaY+margin {
			y = vaY + margin
		}
		if y+winH > vaY+vaH-margin {
			y = vaY + vaH - winH - margin
		}
	}
	return x, y
}

// trayCornerTopRight is the macOS menu-bar / Windows LTR tray default
// (top-right of the work area, y-down coordinates).
func trayCorner(vaX, vaY, vaW, vaH, winW, winH, margin int, topRight bool) (int, int) {
	x := vaX + vaW - winW - margin
	y := vaY + vaH - winH - margin
	if topRight {
		y = vaY + margin
	}
	return clampPos(x, y, winW, winH, vaX, vaY, vaW, vaH, margin)
}

func cursorAnchor(cx, cy, winW, winH, vaX, vaY, vaW, vaH, margin int, below bool) (int, int) {
	x := cx - winW + 24
	y := cy - winH - 8
	if below {
		y = cy + 8
	}
	return clampPos(x, y, winW, winH, vaX, vaY, vaW, vaH, margin)
}
