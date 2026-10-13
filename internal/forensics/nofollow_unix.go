//go:build unix

package forensics

import "syscall"

// openNoFollow refuses to open through a symbolic link.
//
// The collector reads files in world-writable places — the temp directory
// especially — on a host that may already be compromised. Following a link
// planted there would have the agent read, and put into evidence, whatever the
// attacker chose to point it at.
const openNoFollow = syscall.O_NOFOLLOW
