// Package logger provides user-facing console messages and structured
// log/slog records for cryptomotor.
//
// Levels:
//   - default:   warnings and errors from slog, plus every console message;
//   - --verbose: informational records;
//   - --debug:   header fields, nonces, sizes, timings: data stored in the
//     encrypted file anyway, never keys, passwords or plaintext hashes;
//   - --trace:   everything, including the password, derived keys, plaintext
//     hashes and original file names (LevelTrace).
//
// Console messages (Info, Success, Warn, Error) go to stderr, with colours
// only when stderr is a terminal and NO_COLOR is unset. When --log is given,
// the same messages and the enabled slog records are also written to that
// file in slog's text format.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// ANSI color codes used for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

// LevelTrace is the slog level of records that contain secrets.
const LevelTrace = slog.Level(-8)

var (
	once     sync.Once
	mu       sync.Mutex // serialises console and file writes
	logFile  *os.File
	fileSink slog.Handler // nil without --log
	useColor bool
)

// Init configures the global logger. Call once at program startup; later
// calls are ignored. logPath "" disables file logging.
func Init(logPath string, verbose, debug, trace bool) error {
	var initErr error
	once.Do(func() {
		level := slog.LevelWarn
		switch {
		case trace:
			level = LevelTrace
		case debug:
			level = slog.LevelDebug
		case verbose:
			level = slog.LevelInfo
		}
		opts := &slog.HandlerOptions{Level: level, ReplaceAttr: renameTrace}

		var writers []io.Writer
		if logPath != "" {
			if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
				initErr = fmt.Errorf("create log directory: %w", err)
				return
			}
			// 0600: with --trace the file holds passwords and keys.
			f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				initErr = fmt.Errorf("open log file: %w", err)
				return
			}
			logFile = f
			fileSink = slog.NewTextHandler(f, opts)
			writers = append(writers, f)
		}
		writers = append(writers, os.Stderr)
		slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(writers...), opts)))

		useColor = colorWanted(term.IsTerminal(int(os.Stderr.Fd())), os.Getenv("NO_COLOR"))

		if trace {
			Warn("--trace prints the password, derived keys, plaintext hashes and file names. " +
				"Do not use it on a shared system; delete the output and any --log file afterwards.")
		}
	})
	return initErr
}

// colorWanted applies the NO_COLOR convention (https://no-color.org).
func colorWanted(isTerminal bool, noColor string) bool {
	return isTerminal && noColor == ""
}

// renameTrace prints LevelTrace as "TRACE" instead of "DEBUG-4".
func renameTrace(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if l, ok := a.Value.Any().(slog.Level); ok && l == LevelTrace {
			a.Value = slog.StringValue("TRACE")
		}
	}
	return a
}

// Close closes the log file, if any. Call in main's defer.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile, fileSink = nil, nil
	}
}

// TraceEnabled reports whether --trace is on; use it to skip building
// expensive trace attributes.
func TraceEnabled() bool { return slog.Default().Enabled(context.Background(), LevelTrace) }

// DebugEnabled reports whether --debug (or --trace) is on.
func DebugEnabled() bool { return slog.Default().Enabled(context.Background(), slog.LevelDebug) }

// Trace logs a record that may contain secrets; it is shown only with --trace.
func Trace(msg string, args ...any) {
	slog.Log(context.Background(), LevelTrace, msg, args...)
}

// ---------------------------------------------------------------------
// Console messages
// ---------------------------------------------------------------------

// Info prints an informational message.
func Info(format string, args ...any) { emit(slog.LevelInfo, colorCyan, "", format, args) }

// Success prints a success message.
func Success(format string, args ...any) { emit(slog.LevelInfo, colorGreen, "", format, args) }

// Warn prints a warning.
func Warn(format string, args ...any) { emit(slog.LevelWarn, colorYellow, "WARNING: ", format, args) }

// Error prints an error.
func Error(format string, args ...any) { emit(slog.LevelError, colorRed, "ERROR: ", format, args) }

func emit(level slog.Level, color, prefix, format string, args []any) {
	msg := prefix + Clean(fmt.Sprintf(format, args...))
	mu.Lock()
	defer mu.Unlock()
	if useColor {
		fmt.Fprint(os.Stderr, color+msg+colorReset+"\n")
	} else {
		fmt.Fprint(os.Stderr, msg+"\n")
	}
	if fileSink != nil {
		_ = fileSink.Handle(context.Background(), slog.NewRecord(time.Now(), level, msg, 0))
	}
}

// Clean makes a string safe to print on a terminal: control characters,
// Unicode format characters (bidirectional overrides, zero-width marks),
// line separators and invalid UTF-8 bytes are shown as \xNN or \uNNNN
// escapes. A file name from an encrypted file can contain any of them.
func Clean(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && w == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unsafeRune(r) && r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+w])
		}
		i += w
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError ||
		unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}
