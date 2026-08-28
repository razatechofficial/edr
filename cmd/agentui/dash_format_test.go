package main

import "testing"

func TestFormatCount(t *testing.T) {
	if got := formatCount(0); got != "0" {
		t.Fatalf("0 = %q", got)
	}
	if got := formatCount(11); got != "11" {
		t.Fatalf("11 = %q", got)
	}
	if got := formatCount(18400); got != "18.4k" {
		t.Fatalf("18400 = %q", got)
	}
	if got := formatCount(1000); got != "1k" {
		t.Fatalf("1000 = %q", got)
	}
}

func TestCompactAgentID(t *testing.T) {
	if got := compactAgentID("565493cb-c81f-48ef-b418-c087d5674d64"); got != "565493cb" {
		t.Fatalf("got %q", got)
	}
	if got := compactAgentID(""); got != "—" {
		t.Fatalf("empty = %q", got)
	}
}

func TestTrayCornerTopRight(t *testing.T) {
	x, y := trayCorner(0, 25, 1440, 875, 336, 500, 16, true)
	if x != 1440-336-16 {
		t.Fatalf("x=%d", x)
	}
	if y != 25+16 {
		t.Fatalf("y=%d want just below menu bar", y)
	}
}

func TestClampPos(t *testing.T) {
	x, y := clampPos(-40, -10, 336, 500, 0, 0, 800, 600, 8)
	if x != 8 || y != 8 {
		t.Fatalf("got %d,%d", x, y)
	}
}

func TestRamHint(t *testing.T) {
	got := ramHint(14<<30+214748365, 16<<30)
	if got != "14.2 / 16 GB" {
		t.Fatalf("got %q", got)
	}
}

func TestRamBreakdown(t *testing.T) {
	res := resourceSnapshot{
		AgentMemMB: 140,
		OtherMem:   24 << 30,
		SysMemTot:  32 << 30,
		FreeMem:    8 << 30,
	}
	got := ramBreakdown(res)
	if got != "other 24 GB · total 32 GB" {
		t.Fatalf("got %q", got)
	}
	v, u := formatAgentRAM(140)
	if v != "140" || u != "MB" {
		t.Fatalf("agent ram %s %s", v, u)
	}
}

func TestCpuBreakdown(t *testing.T) {
	got := cpuBreakdown(resourceSnapshot{AgentCPU: 0.6, OtherCPU: 20.94, SysCPU: 21})
	if got != "system 21% · idle 79%" {
		t.Fatalf("rounded-equal = %q", got)
	}
	got = cpuBreakdown(resourceSnapshot{AgentCPU: 8, OtherCPU: 16, SysCPU: 24})
	if got != "other 16% · system 24%" {
		t.Fatalf("distinct = %q", got)
	}
}

func TestBusyCPU(t *testing.T) {
	if got := busyCPU(10, 10, 10, 10); got != 0 {
		t.Fatalf("no delta = %v", got)
	}
	// 80 idle of 100 ticks → 20% busy
	got := busyCPU(0, 0, 80, 100)
	if got < 19.9 || got > 20.1 {
		t.Fatalf("busy = %v", got)
	}
}

func TestParseEtime(t *testing.T) {
	if got := parseEtime("04:12"); got != "4m" {
		t.Fatalf("mm:ss = %q", got)
	}
	if got := parseEtime("1:04:12"); got != "1h 4m" {
		t.Fatalf("hh:mm:ss = %q", got)
	}
	if got := parseEtime("2-01:04:12"); got != "2d 1h" {
		t.Fatalf("dd-hh = %q", got)
	}
}

func TestDrawAreaSparkShortSeries(t *testing.T) {
	col := colorOK
	for _, vals := range [][]float64{nil, {}, {1.2}, {1.2, 1.8, 2.1}} {
		img := drawAreaSpark(0, 0, vals, col)
		if img == nil || img.Bounds().Empty() {
			t.Fatalf("vals=%v produced empty spark", vals)
		}
	}
}
