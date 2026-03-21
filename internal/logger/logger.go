// Package logger provides a thin wrapper around the standard log/slog
// package with colorized console output and rotating file logging.
//
// Design decisions:
//   - NEVER log key material, salts, or nonces — even at debug level.
//   - Colorized stderr output for interactive use; plain text for log files.
//   - Singleton pattern via Init/Get to avoid passing loggers everywhere.
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// ANSI color codes used for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

var (
	instance *slog.Logger
	once     sync.Once
	logFile  *os.File
)

// Init creates the global logger. Call once at program startup.
// logPath is the file path for the persistent log; pass "" to disable file logging.
// verbose enables INFO-level console output; debug enables DEBUG-level.
func Init(logPath string, verbose, debug bool) error {
	var initErr error
	once.Do(func() {
		level := slog.LevelWarn
		if debug {
			level = slog.LevelDebug
		} else if verbose {
			level = slog.LevelInfo
		}

		var writers []io.Writer

		// File handler (plain text, always DEBUG level for post-mortem analysis).
		if logPath != "" {
			dir := filepath.Dir(logPath)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				initErr = fmt.Errorf("create log directory: %w", err)
				return
			}
			f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
			if err != nil {
				initErr = fmt.Errorf("open log file: %w", err)
				return
			}
			logFile = f
			writers = append(writers, f)
		}

		// Console handler (stderr, respects verbosity level).
		writers = append(writers, os.Stderr)

		w := io.MultiWriter(writers...)
		instance = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
			Level: level,
		}))

		// Set as default so slog.Debug() etc. work without passing the logger.
		slog.SetDefault(instance)

		if debug {
			fmt.Fprintf(os.Stderr,
				colorYellow+"WARNING: Debug mode is ON — keys, salts, nonces, and HMAC values "+
					"will be written to logs. Do NOT use --debug in production."+colorReset+"\n")
		}
	})
	return initErr
}

// Get returns the global logger. Panics if Init was not called.
func Get() *slog.Logger {
	if instance == nil {
		// Fallback: create a minimal logger so we don't crash.
		instance = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}
	return instance
}

// Close flushes and closes the log file, if any. Call in main's defer.
func Close() {
	if logFile != nil {
		_ = logFile.Close()
	}
}

// ---------------------------------------------------------------------
// Convenience wrappers with color for direct console messages.
// These bypass slog and print to stderr with ANSI colors.
// Use for user-facing status lines, NOT for structured log records.
// ---------------------------------------------------------------------

// Info prints a cyan informational message to stderr.
func Info(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorCyan+format+colorReset+"\n", args...)
}

// Success prints a green success message to stderr.
func Success(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorGreen+format+colorReset+"\n", args...)
}

// Warn prints a yellow warning message to stderr.
func Warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorYellow+"WARNING: "+format+colorReset+"\n", args...)
}

// Error prints a red error message to stderr.
func Error(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorRed+"ERROR: "+format+colorReset+"\n", args...)
}
