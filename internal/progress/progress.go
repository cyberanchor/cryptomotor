// Package progress provides a simple terminal progress bar for long-running
// file operations such as hashing and encryption.
//
// It writes directly to stderr so it never interferes with stdout data.
// Updates are throttled to avoid excessive terminal I/O. Callers create bars
// only when stderr is a terminal (see Options.ShowProgress).
package progress

import (
	"fmt"
	"os"
	"sync"
	"time"

	"cryptomotor/internal/config"
)

// Bar tracks and renders progress of a single operation.
type Bar struct {
	mu       sync.Mutex
	total    int64
	current  int64
	label    string
	start    time.Time
	lastDraw time.Time
	done     bool
}

// New creates a progress bar with a descriptive label and total byte count.
// If total is 0 or negative, the bar operates in indeterminate mode.
func New(label string, total int64) *Bar {
	now := time.Now()
	return &Bar{
		total:    total,
		label:    label,
		start:    now,
		lastDraw: now,
	}
}

// Add increments the current position by n bytes and redraws if the
// throttle interval has elapsed.
func (b *Bar) Add(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.current += n
	if b.total > 0 && b.current > b.total {
		b.current = b.total
	}

	now := time.Now()
	if now.Sub(b.lastDraw) >= config.ProgressInterval {
		b.draw(now)
		b.lastDraw = now
	}
}

// Finish marks the bar as complete and draws the final state.
func (b *Bar) Finish() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.total > 0 {
		b.current = b.total
	}
	b.done = true
	b.draw(time.Now())
	fmt.Fprint(os.Stderr, "\n")
}

// draw renders the bar to stderr. Caller must hold b.mu.
func (b *Bar) draw(now time.Time) {
	if b.total <= 0 {
		fmt.Fprintf(os.Stderr, "\r  %s: %s processed", b.label, humanBytes(b.current))
		return
	}

	pct := float64(b.current) / float64(b.total)
	if pct > 1 {
		pct = 1
	}

	const barWidth = 30
	filled := int(pct * barWidth)

	elapsed := now.Sub(b.start)
	speed := float64(0)
	if elapsed.Seconds() > 0 {
		speed = float64(b.current) / elapsed.Seconds()
	}

	eta := ""
	if speed > 0 && !b.done {
		remaining := float64(b.total-b.current) / speed
		eta = fmt.Sprintf(" ETA %s", (time.Duration(remaining) * time.Second).Truncate(time.Second))
	}

	bar := make([]byte, barWidth)
	for i := range bar {
		if i < filled {
			bar[i] = '#'
		} else {
			bar[i] = '-'
		}
	}

	fmt.Fprintf(os.Stderr, "\r  %s [%s] %5.1f%% %s/s%s   ",
		b.label, string(bar), pct*100, humanBytes(int64(speed)), eta)
}

// humanBytes formats a byte count into a human-readable string.
func humanBytes(b int64) string {
	const (
		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
