package detection

import (
	"sync"
	"time"
)

const (
	cloneNewNS  = 0x00020000
	cloneNewPID = 0x20000000
)

type containerState struct {
	ProcessName string
	UnshareTS   time.Time
	HasMount    bool
	HasCapSys   bool
}

// ContainerCorrelator correlates unshare/mount/capability signals for escape-like behavior.
type ContainerCorrelator struct {
	mu     sync.Mutex
	window time.Duration
	state  map[int]*containerState
}

func NewContainerCorrelator() *ContainerCorrelator {
	return &ContainerCorrelator{
		window: 5 * time.Second,
		state:  make(map[int]*containerState),
	}
}

func (c *ContainerCorrelator) ObserveUnshare(pid int, processName string, flags uint64, ts time.Time) {
	if flags&(cloneNewNS|cloneNewPID) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.state[pid]
	if st == nil {
		st = &containerState{}
		c.state[pid] = st
	}
	st.ProcessName = processName
	st.UnshareTS = ts
}

func (c *ContainerCorrelator) ObserveMount(pid int, ts time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.state[pid]
	if st == nil {
		st = &containerState{}
		c.state[pid] = st
	}
	st.HasMount = true
	if st.UnshareTS.IsZero() {
		st.UnshareTS = ts
	}
}

func (c *ContainerCorrelator) ObserveCapSysAdmin(pid int, hasCap bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.state[pid]
	if st == nil {
		st = &containerState{}
		c.state[pid] = st
	}
	st.HasCapSys = hasCap
}

// Correlate returns "namespace_escape:pid:procname" strings for matched states.
func (c *ContainerCorrelator) Correlate() []string {
	now := time.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for pid, st := range c.state {
		if st.UnshareTS.IsZero() || now.Sub(st.UnshareTS) > c.window {
			delete(c.state, pid)
			continue
		}
		if st.HasMount && st.HasCapSys {
			out = append(out, "namespace_escape:"+itoa(pid)+":"+st.ProcessName)
			delete(c.state, pid)
		}
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
