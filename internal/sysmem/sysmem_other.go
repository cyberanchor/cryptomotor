//go:build !linux && !windows

package sysmem

// available is unknown on other systems: callers then assume enough memory.
func available() (uint64, bool) { return 0, false }
