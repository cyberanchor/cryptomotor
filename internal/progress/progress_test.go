package progress

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStderr runs fn with os.Stderr redirected and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	return <-done
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:               "0 B",
		1023:            "1023 B",
		1024:            "1.0 KiB",
		1536:            "1.5 KiB",
		1<<20 - 1:       "1024.0 KiB",
		1 << 20:         "1.0 MiB",
		64 << 20:        "64.0 MiB",
		1 << 30:         "1.0 GiB",
		5<<30 + 512<<20: "5.5 GiB",
		-5:              "-5 B",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestBarClampsAndFinishes(t *testing.T) {
	out := captureStderr(t, func() {
		b := New("Testing", 100)
		b.Add(40)
		b.Add(1000) // more than total
		if b.current != 100 {
			t.Errorf("current = %d after overshoot, want clamp to 100", b.current)
		}
		b.Finish()
		if !b.done {
			t.Error("Finish did not mark the bar done")
		}
	})
	if !strings.Contains(out, "Testing [##############################] 100.0%") {
		t.Fatalf("final frame missing: %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("Finish must end the line: %q", out)
	}
	if strings.Contains(out, "ETA") {
		t.Fatalf("finished bar must not show an ETA: %q", out)
	}
}

func TestBarThrottle(t *testing.T) {
	out := captureStderr(t, func() {
		b := New("Throttle", 1000)
		for i := 0; i < 100; i++ {
			b.Add(1) // all within one ProgressInterval: no frame
		}
	})
	if out != "" {
		t.Fatalf("Add redrew %d times within the throttle interval: %q", strings.Count(out, "\r"), out)
	}
}

func TestBarDrawsETAAfterInterval(t *testing.T) {
	out := captureStderr(t, func() {
		b := New("Slow", 1000)
		b.start = time.Now().Add(-2 * time.Second)
		b.lastDraw = time.Now().Add(-time.Second)
		b.Add(500)
	})
	if !strings.Contains(out, " 50.0%") || !strings.Contains(out, "ETA ") || !strings.HasPrefix(out, "\r") {
		t.Fatalf("mid-run frame should show 50%% and an ETA: %q", out)
	}
}

func TestBarIndeterminate(t *testing.T) {
	out := captureStderr(t, func() {
		b := New("Stream", 0)
		b.Add(2048)
		b.Finish()
	})
	if !strings.Contains(out, "Stream: ") || !strings.Contains(out, " processed") {
		t.Fatalf("indeterminate bar output: %q", out)
	}
}

// CM-25: an indeterminate bar (total <= 0) counts the bytes it is given.
func TestBarIndeterminateCountsBytes(t *testing.T) {
	out := captureStderr(t, func() {
		b := New("Stream", 0)
		b.Add(2048)
		b.draw(b.start)
		b.Finish()
	})
	if strings.Count(out, "Stream: 2.0 KiB processed") != 2 {
		t.Fatalf("indeterminate bar output: %q", out)
	}
}
