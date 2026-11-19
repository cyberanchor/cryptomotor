package logger

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The logger is a process-wide singleton (sync.Once), so every Init scenario
// runs in a child process: the test binary re-executes itself with
// LOGGER_HELPER set and TestMain dispatches to the scenario.
func TestMain(m *testing.M) {
	if mode := os.Getenv("LOGGER_HELPER"); mode != "" {
		runHelper(mode, os.Getenv("LOGGER_PATH"))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runHelper(mode, path string) {
	switch mode {
	case "debug-file":
		if err := Init(path, false, true, false); err != nil {
			fmt.Println("ERR:", err)
			return
		}
		slog.Debug("debug record", "k", "v")
		Trace("trace record", "secret", "s3cr3t")
		Close()
	case "trace-file":
		_ = Init(path, false, false, true)
		Trace("trace record", "secret", "s3cr3t")
		fmt.Println("TRACE:", TraceEnabled(), DebugEnabled())
		Close()
	case "verbose-file":
		_ = Init(path, true, false, false)
		Info("hello from Info %d", 1)
		Success("hello from Success")
		Warn("hello from Warn")
		Error("hello from Error with \x1b[2J escape")
		slog.Debug("slog debug record")
		fmt.Println("TRACE:", TraceEnabled(), DebugEnabled())
		Close()
	case "default-level":
		_ = Init("", false, false, false)
		slog.Info("info record hidden")
		slog.Warn("warn record shown")
	case "bad-path":
		fmt.Println("ERR:", Init(path, false, false, false))
	case "init-twice":
		e1 := Init("", false, false, false)
		e2 := Init(path, false, true, false)
		fmt.Println("E1:", e1, "E2:", e2)
		slog.Debug("debug after second Init")
	}
}

func helper(t *testing.T, mode, path string, env ...string) (string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), "LOGGER_HELPER="+mode, "LOGGER_PATH="+path), env...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper %s: %v\nstdout: %s\nstderr: %s", mode, err, out.String(), errb.String())
	}
	return out.String(), errb.String()
}

func TestDebugShowsNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "run.log")
	out, errOut := helper(t, "debug-file", path)
	if strings.Contains(out, "ERR:") {
		t.Fatal(out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("log file not created (MkdirAll of parent dirs): %v", err)
	}
	if !strings.Contains(string(data), `msg="debug record" k=v`) || !strings.Contains(errOut, `msg="debug record" k=v`) {
		t.Fatalf("debug record must reach file and stderr\nfile: %q\nstderr: %q", data, errOut)
	}
	if strings.Contains(string(data)+errOut, "s3cr3t") {
		t.Fatal("--debug printed a trace-level (secret) record")
	}
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm&0o077 != 0 {
		t.Fatalf("log file mode %o is readable by others", perm)
	}
}

func TestTraceShowsSecretsAndWarns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	out, errOut := helper(t, "trace-file", path)
	data, _ := os.ReadFile(path)
	if !strings.Contains(out, "TRACE: true true") {
		t.Fatalf("trace and debug must be enabled: %q", out)
	}
	for _, where := range []string{errOut, string(data)} {
		if !strings.Contains(where, `level=TRACE msg="trace record" secret=s3cr3t`) {
			t.Errorf("trace record missing or not labelled TRACE: %q", where)
		}
		if !strings.Contains(where, "--trace prints the password") {
			t.Errorf("trace warning missing: %q", where)
		}
	}
}

// CM-13: --log receives every console message, not only slog records.
func TestLogFileReceivesConsoleMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.log")
	out, errOut := helper(t, "verbose-file", path)
	data, _ := os.ReadFile(path)
	for _, want := range []string{"hello from Info 1", "hello from Success", "WARNING: hello from Warn", "ERROR: hello from Error"} {
		if !strings.Contains(errOut, want) || !strings.Contains(string(data), want) {
			t.Errorf("%q missing from stderr or log file\nstderr: %q\nfile: %q", want, errOut, data)
		}
	}
	if strings.Contains(errOut, "slog debug record") || !strings.Contains(out, "TRACE: false false") {
		t.Error("debug record printed although only --verbose was set")
	}
	// stderr is a pipe here: no colour codes, and the escape from the message is neutralised.
	if strings.Contains(errOut, "\x1b") || !strings.Contains(errOut, `with \x1b[2J escape`) {
		t.Errorf("stderr must contain no raw ESC: %q", errOut)
	}
}

func TestDefaultLevelIsWarn(t *testing.T) {
	_, errOut := helper(t, "default-level", "")
	if strings.Contains(errOut, "info record hidden") || !strings.Contains(errOut, "warn record shown") {
		t.Fatalf("default level should be WARN: %q", errOut)
	}
}

func TestInitBadPath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := helper(t, "bad-path", filepath.Join(blocker, "sub", "x.log"))
	if !strings.Contains(out, "create log directory") {
		t.Fatalf("Init under a regular file should fail with 'create log directory': %q", out)
	}
	out, _ = helper(t, "bad-path", dir) // a directory as the log file
	if !strings.Contains(out, "open log file") {
		t.Fatalf("Init with a directory path should fail with 'open log file': %q", out)
	}
}

func TestInitTwiceKeepsFirstConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "second.log")
	out, errOut := helper(t, "init-twice", path)
	if !strings.Contains(out, "E1: <nil> E2: <nil>") {
		t.Fatalf("unexpected errors: %q", out)
	}
	if _, err := os.Stat(path); err == nil || strings.Contains(errOut, "debug after second Init") {
		t.Fatalf("second Init must be a no-op (sync.Once)")
	}
}

func TestColorWanted(t *testing.T) {
	cases := []struct {
		tty     bool
		noColor string
		want    bool
	}{{true, "", true}, {true, "1", false}, {false, "", false}, {false, "1", false}}
	for _, c := range cases {
		if got := colorWanted(c.tty, c.noColor); got != c.want {
			t.Errorf("colorWanted(%v, %q) = %v", c.tty, c.noColor, got)
		}
	}
}

// CM-10: names from encrypted files may contain terminal control sequences.
func TestClean(t *testing.T) {
	cases := map[string]string{
		"plain name.txt": "plain name.txt",
		"документ 密码 αβγ → done":            "документ 密码 αβγ → done",
		"\x1b]0;TITLE\x07\x1b[2K\rnice.txt": `\x1b]0;TITLE\x07\x1b[2K\x0dnice.txt`,
		"new\nline":                         `new\x0aline`,
		"evil\u202etxt.exe":                 `evil\u202etxt.exe`,
		"c1\u009bcontrol":                   `c1\u009bcontrol`,
		"bad\xffutf8":                       `bad\xffutf8`,
		"tab\tsep":                          `tab\x09sep`,
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}
