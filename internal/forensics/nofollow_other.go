//go:build !unix

package forensics

// openNoFollow has no equivalent flag on platforms without one. The Lstat check
// before each read is what guards the path there.
const openNoFollow = 0
