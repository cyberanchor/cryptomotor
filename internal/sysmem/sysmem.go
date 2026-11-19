// Package sysmem reports how much memory is available for a new allocation.
//
// It is used before Argon2id with the 4 GiB cost: a derivation that does not
// fit in RAM swaps for a very long time, or the process is killed for lack of
// memory, instead of failing cleanly.
package sysmem

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Available returns the number of bytes that can be allocated without
// swapping, and false when this cannot be determined on the current system.
func Available() (uint64, bool) { return available() }

// parseMeminfo extracts MemAvailable (in bytes) from /proc/meminfo content.
func parseMeminfo(r io.Reader) (uint64, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "MemAvailable:" {
			kib, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return 0, false
			}
			return kib * 1024, true
		}
	}
	return 0, false
}

// cgroupRoom returns memory.max - memory.current of a cgroup v2 group, or
// false when the group has no limit ("max") or the values are
// unreadable.
func cgroupRoom(limit, current string) (uint64, bool) {
	limit, current = strings.TrimSpace(limit), strings.TrimSpace(current)
	if limit == "" || limit == "max" {
		return 0, false
	}
	lim, err1 := strconv.ParseUint(limit, 10, 64)
	used, err2 := strconv.ParseUint(current, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	if used >= lim {
		return 0, true
	}
	return lim - used, true
}
