package sysmem

import (
	"os"
	"path/filepath"
	"strings"
)

// available takes MemAvailable from /proc/meminfo and, when the process runs
// in a cgroup v2 group with a memory limit (containers, systemd scopes), the
// room left under that limit, whichever is smaller.
func available() (uint64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	avail, ok := parseMeminfo(f)
	f.Close()
	if !ok {
		return 0, false
	}
	if room, ok := cgroupAvailable(); ok && room < avail {
		avail = room
	}
	return avail, true
}

// cgroupAvailable walks from the process's cgroup up to the root and returns
// the smallest room left under any memory.max on the way.
func cgroupAvailable() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, false
	}
	var rel string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") { // cgroup v2 unified hierarchy
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if rel == "" {
		return 0, false
	}
	var best uint64
	found := false
	for dir := filepath.Join("/sys/fs/cgroup", rel); strings.HasPrefix(dir, "/sys/fs/cgroup"); dir = filepath.Dir(dir) {
		limit, err1 := os.ReadFile(filepath.Join(dir, "memory.max"))
		cur, err2 := os.ReadFile(filepath.Join(dir, "memory.current"))
		if err1 == nil && err2 == nil {
			if room, ok := cgroupRoom(string(limit), string(cur)); ok && (!found || room < best) {
				best, found = room, true
			}
		}
		if dir == "/sys/fs/cgroup" {
			break
		}
	}
	return best, found
}
