package sysmem

import (
	"runtime"
	"strings"
	"testing"
)

func TestParseMeminfo(t *testing.T) {
	const sample = "MemTotal:         979372 kB\nMemFree:           71408 kB\nMemAvailable:     229264 kB\nBuffers:            1812 kB\n"
	got, ok := parseMeminfo(strings.NewReader(sample))
	if !ok || got != 229264*1024 {
		t.Fatalf("got %d %v", got, ok)
	}
	for _, bad := range []string{"", "MemTotal: 1 kB\n", "MemAvailable: lots kB\n"} {
		if _, ok := parseMeminfo(strings.NewReader(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestCgroupRoom(t *testing.T) {
	cases := []struct {
		max, cur string
		want     uint64
		ok       bool
	}{
		{"max\n", "1000\n", 0, false},
		{"", "1", 0, false},
		{"545259520\n", "45259520\n", 500000000, true},
		{"100\n", "200\n", 0, true}, // over the limit: no room
		{"junk", "1", 0, false},
	}
	for _, c := range cases {
		got, ok := cgroupRoom(c.max, c.cur)
		if got != c.want || ok != c.ok {
			t.Errorf("cgroupRoom(%q, %q) = %d %v, want %d %v", c.max, c.cur, got, ok, c.want, c.ok)
		}
	}
}

func TestAvailableOnThisSystem(t *testing.T) {
	got, ok := Available()
	switch runtime.GOOS {
	case "linux", "windows":
		if !ok || got == 0 {
			t.Fatalf("Available() = %d %v on %s", got, ok, runtime.GOOS)
		}
	default:
		if ok {
			t.Fatalf("Available() should be unknown on %s", runtime.GOOS)
		}
	}
}
