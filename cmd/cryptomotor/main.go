// cryptomotor — cross-platform file encryption tool.
//
// Usage:
//
//	cryptomotor --encrypt --folder ./data --password mypass
//	cryptomotor --decrypt --file ./encrypted/abc123 --password-file key.txt
//	cryptomotor --analyze --file ./encrypted/abc123 --debug
//
// Cryptographic stack:
//
//	Key derivation:  Argon2id  (4 GiB / 8 iterations / 8 threads; 64 MiB with
//	                 --low-memory or when less than 8 GiB of RAM is free)
//	AEAD cipher:     XChaCha20-Poly1305 (default) or AES-256-GCM (--aes)
//	Integrity:       HMAC-SHA512 (Encrypt-then-MAC)
//	File hash:       SHA-512
//
// See README.md for the full protocol specification.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/term"

	"cryptomotor/internal/config"
	"cryptomotor/internal/fileproc"
	"cryptomotor/internal/logger"
)

func main() {
	// -----------------------------------------------------------------
	// Define flags
	// -----------------------------------------------------------------
	encrypt := flag.Bool("encrypt", false, "Encrypt files in the specified folder or file")
	decrypt := flag.Bool("decrypt", false, "Decrypt files in the specified folder or file")
	analyze := flag.Bool("analyze", false, "Analyze the system block of an encrypted file (no password needed)")
	folder := flag.String("folder", "", "Folder to process: every regular file directly inside it")
	file := flag.String("file", "", "Single file to process or analyze")
	passwordFlag := flag.String("password", "", "Password for encryption/decryption (prefer --password-file or prompt)")
	passwordFile := flag.String("password-file", "", "Path to a UTF-8 file containing the password (a BOM and trailing line breaks are removed)")
	useAES := flag.Bool("aes", false, "Encrypt with AES-256-GCM instead of XChaCha20-Poly1305")
	lowMemory := flag.Bool("low-memory", false, "Encrypt with a 64 MiB Argon2id cost instead of 4 GiB (recorded in the file)")
	force := flag.Bool("force", false, "Replace existing output files when decrypting")
	verbose := flag.Bool("verbose", false, "Enable informational console output")
	debug := flag.Bool("debug", false, "Debug output: header fields, nonces, sizes, timings (no keys or passwords)")
	trace := flag.Bool("trace", false, "Everything --debug shows plus the password, derived keys, plaintext hashes and names (SENSITIVE)")
	dryRun := flag.Bool("dry-run", false, "Simulate operations without writing any files")
	noProgress := flag.Bool("no-progress", false, "Disable progress bars (they are shown only on a terminal)")
	logPath := flag.String("log", "", "Also write all messages to this file (mode 0600, appended)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s v%s — cross-platform file encryption tool\n\n",
			config.ProgramName, config.ProgramVersion)
		fmt.Fprintf(os.Stderr, "Cipher: XChaCha20-Poly1305 (default) or AES-256-GCM (--aes)\n")
		fmt.Fprintf(os.Stderr, "KDF:    Argon2id (4 GiB / 8 iter / 8 threads; 64 MiB with --low-memory)\n\n")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  cryptomotor --encrypt --folder ./data --password mypass")
		fmt.Fprintln(os.Stderr, "  cryptomotor --decrypt --file ./enc/abc123 --password-file key.txt")
		fmt.Fprintln(os.Stderr, "  cryptomotor --analyze --file ./enc/abc123 --debug")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Exit status: 0 success, 1 error (in folder mode: any file failed), 2 bad flag,")
		fmt.Fprintln(os.Stderr, "             130 interrupted (SIGINT), 143 terminated (SIGTERM)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	// -----------------------------------------------------------------
	// Initialize logger
	// -----------------------------------------------------------------
	if *trace {
		*debug = true
	}
	if *debug {
		*verbose = true
	}
	if err := logger.Init(*logPath, *verbose, *debug, *trace); err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()
	handleSignals()

	// -----------------------------------------------------------------
	// Validate flag combinations
	// -----------------------------------------------------------------
	if err := validateFlags(*encrypt, *decrypt, *analyze, *folder, *file, *passwordFlag, *passwordFile, flag.Args()); err != nil {
		logger.Error("%v", err)
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		exit(1)
	}

	// -----------------------------------------------------------------
	// Banner
	// -----------------------------------------------------------------
	switch {
	case *encrypt:
		cipherName := config.CipherChaCha20Poly1305.String()
		if *useAES {
			cipherName = config.CipherAES256GCM.String()
		}
		memLabel := "4 GiB (64 MiB if less than 8 GiB of RAM is free)"
		if *lowMemory {
			memLabel = "64 MiB"
		}
		logger.Info("%s v%s  |  encrypt  |  cipher=%s  Argon2id=%s/%d iter/%d threads",
			config.ProgramName, config.ProgramVersion, cipherName, memLabel, config.Argon2Time, config.Argon2Threads)
	case *decrypt:
		logger.Info("%s v%s  |  decrypt  |  cipher and Argon2id cost are read from each file",
			config.ProgramName, config.ProgramVersion)
	}
	logger.Trace("Options",
		"encrypt", *encrypt, "decrypt", *decrypt, "analyze", *analyze,
		"folder", *folder, "file", *file, "password_file", *passwordFile,
		"aes", *useAES, "low_memory", *lowMemory, "force", *force,
		"dry_run", *dryRun, "no_progress", *noProgress, "log", *logPath,
	)

	// -----------------------------------------------------------------
	// Analyze (no password needed)
	// -----------------------------------------------------------------
	if *analyze {
		if err := fileproc.AnalyzeFile(*file, *debug); err != nil {
			logger.Error("%v", err)
			exit(1)
		}
		exit(0)
	}

	// -----------------------------------------------------------------
	// Obtain password
	// -----------------------------------------------------------------
	password, source, err := resolvePassword(*passwordFlag, *passwordFile)
	if err != nil {
		logger.Error("%v", err)
		exit(1)
	}
	logger.Trace("Password", "source", source, "value", string(password), "bytes", len(password))
	if len(password) == 0 {
		logger.Error("password is empty")
		exit(1)
	}
	if len(password) > config.MaxPasswordLen {
		logger.Warn("Password length (%d bytes) exceeds recommended maximum (%d). Continuing anyway.",
			len(password), config.MaxPasswordLen)
	}

	// -----------------------------------------------------------------
	// Build options
	// -----------------------------------------------------------------
	opts := fileproc.Options{
		CipherID:     config.CipherChaCha20Poly1305,
		LowMemory:    *lowMemory,
		Verbose:      *verbose,
		Debug:        *debug,
		DryRun:       *dryRun,
		ShowProgress: !*noProgress && term.IsTerminal(int(os.Stderr.Fd())),
		Force:        *force,
	}
	if *useAES {
		opts.CipherID = config.CipherAES256GCM
	}

	// -----------------------------------------------------------------
	// Execute
	// -----------------------------------------------------------------
	mode := "encrypt"
	if *decrypt {
		mode = "decrypt"
	}

	if *folder != "" {
		if err := fileproc.ProcessFolder(*folder, password, mode, opts); err != nil {
			logger.Error("%v", err)
			exit(1)
		}
		exit(0)
	}

	// Single file mode.
	switch mode {
	case "encrypt":
		outDir := filepath.Join(filepath.Dir(*file), "encrypted")
		if _, err := fileproc.EncryptFile(*file, outDir, password, opts); err != nil {
			logger.Error("%v", err)
			exit(1)
		}
	case "decrypt":
		outDir := filepath.Join(filepath.Dir(*file), "decrypted")
		if _, err := fileproc.DecryptFile(*file, outDir, password, opts); err != nil {
			logger.Error("%v", err)
			exit(1)
		}
	}
	exit(0)
}

// exit closes the log file (deferred calls do not run on os.Exit) and exits.
func exit(code int) {
	logger.Close()
	os.Exit(code)
}

// ---------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------

var (
	termMu    sync.Mutex
	termState *term.State // terminal mode saved while the password prompt is open
)

// handleSignals makes SIGINT and SIGTERM restore the terminal, remove partial
// output files and exit with 130 or 143. A SIGINT that was ignored when the
// program started (a background job of a script) stays ignored.
func handleSignals() {
	sigs := []os.Signal{syscall.SIGTERM}
	if !signal.Ignored(os.Interrupt) {
		sigs = append(sigs, os.Interrupt)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	go func() {
		s := <-ch
		termMu.Lock()
		if termState != nil {
			_ = term.Restore(int(os.Stdin.Fd()), termState)
			fmt.Fprintln(os.Stderr)
		}
		termMu.Unlock()
		removed := fileproc.Abort()
		logger.Error("interrupted (%v): removed %d partial file(s)", s, len(removed))
		code := 130
		if s == syscall.SIGTERM {
			code = 143
		}
		exit(code)
	}()
}

// ---------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------

func validateFlags(encrypt, decrypt, analyze bool, folder, file, password, passwordFile string, extra []string) error {
	if len(extra) > 0 {
		return fmt.Errorf("unexpected argument %q (flags start with --)", extra[0])
	}
	modes := 0
	if encrypt {
		modes++
	}
	if decrypt {
		modes++
	}
	if analyze {
		modes++
	}
	if modes == 0 {
		return fmt.Errorf("specify one of --encrypt, --decrypt, or --analyze")
	}
	if modes > 1 {
		return fmt.Errorf("specify only one of --encrypt, --decrypt, or --analyze")
	}
	if analyze && file == "" {
		return fmt.Errorf("--analyze requires --file")
	}
	if (encrypt || decrypt) && folder == "" && file == "" {
		return fmt.Errorf("--encrypt/--decrypt requires --folder or --file")
	}
	if folder != "" && file != "" {
		return fmt.Errorf("specify either --folder or --file, not both")
	}
	if password != "" && passwordFile != "" {
		return fmt.Errorf("specify either --password or --password-file, not both")
	}

	// Verify paths exist.
	if folder != "" {
		info, err := os.Stat(folder)
		if err != nil {
			return fmt.Errorf("folder %q: %w", folder, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%q is not a directory", folder)
		}
	}
	if file != "" {
		info, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("file %q: %w", file, err)
		}
		if info.IsDir() {
			return fmt.Errorf("%q is a directory, use --folder instead", file)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Password resolution
// ---------------------------------------------------------------------

// utf8BOM is what Notepad and other editors put in front of "UTF-8 with BOM" files.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// resolvePassword returns the password and where it came from. A password
// file loses a leading UTF-8 BOM and trailing line breaks (\n, \r\n), nothing
// else: spaces and tabs belong to the password, as with --password.
func resolvePassword(flagPass, flagFile string) ([]byte, string, error) {
	if flagPass != "" {
		return []byte(flagPass), "--password", nil
	}
	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			return nil, "", fmt.Errorf("read password file: %w", err)
		}
		data = bytes.TrimPrefix(data, utf8BOM)
		data = bytes.TrimRight(data, "\r\n")
		return data, "--password-file", nil
	}

	// Interactive prompt — read from terminal without echo.
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, "", errors.New("read password from terminal: stdin is not a terminal (use --password-file)")
	}
	state, err := term.GetState(fd)
	if err != nil {
		return nil, "", fmt.Errorf("read password from terminal: %w", err)
	}
	termMu.Lock()
	termState = state
	termMu.Unlock()
	fmt.Fprint(os.Stderr, "Enter password: ")
	pass, err := term.ReadPassword(fd)
	termMu.Lock()
	termState = nil
	termMu.Unlock()
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, "", fmt.Errorf("read password from terminal: %w", err)
	}
	return pass, "prompt", nil
}
