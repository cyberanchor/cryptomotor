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
//	Key derivation:  Argon2id  (4 GiB / 8 iterations / 8 threads)
//	AEAD cipher:     XChaCha20-Poly1305 (default) or AES-256-GCM (--aes)
//	Integrity:       HMAC-SHA512 (Encrypt-then-MAC)
//	File hash:       SHA-512
//
// See README.md for the full protocol specification.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	analyze := flag.Bool("analyze", false, "Analyze the system block of an encrypted file")
	folder := flag.String("folder", "", "Folder to process (required for encrypt/decrypt batch mode)")
	file := flag.String("file", "", "Single file to process or analyze")
	passwordFlag := flag.String("password", "", "Password for encryption/decryption (prefer --password-file or prompt)")
	passwordFile := flag.String("password-file", "", "Path to a UTF-8 file containing the password")
	useAES := flag.Bool("aes", false, "Use AES-256-GCM instead of XChaCha20-Poly1305")
	lowMemory := flag.Bool("low-memory", false, "Use 64 MiB Argon2id memory cost (instead of 4 GiB)")
	verbose := flag.Bool("verbose", false, "Enable informational console output")
	debug := flag.Bool("debug", false, "Enable detailed debug output including system block hex dumps")
	dryRun := flag.Bool("dry-run", false, "Simulate operations without writing any files")
	noProgress := flag.Bool("no-progress", false, "Disable progress bars")
	logPath := flag.String("log", "", "Path to log file (default: no file logging)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s v%s — cross-platform file encryption tool\n\n",
			config.ProgramName, config.ProgramVersion)
		fmt.Fprintf(os.Stderr, "Cipher: XChaCha20-Poly1305 (default) or AES-256-GCM (--aes)\n")
		fmt.Fprintf(os.Stderr, "KDF:    Argon2id (4 GiB / 8 iter / 8 threads)\n\n")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  cryptomotor --encrypt --folder ./data --password mypass")
		fmt.Fprintln(os.Stderr, "  cryptomotor --decrypt --file ./enc/abc123 --password-file key.txt")
		fmt.Fprintln(os.Stderr, "  cryptomotor --analyze --file ./enc/abc123 --debug")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	// -----------------------------------------------------------------
	// Initialize logger
	// -----------------------------------------------------------------
	if err := logger.Init(*logPath, *verbose, *debug); err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// -----------------------------------------------------------------
	// Validate flag combinations
	// -----------------------------------------------------------------
	if err := validateFlags(*encrypt, *decrypt, *analyze, *folder, *file, *passwordFlag, *passwordFile); err != nil {
		logger.Error("%v", err)
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	// -----------------------------------------------------------------
	// Banner
	// -----------------------------------------------------------------
	cipherName := "XChaCha20-Poly1305"
	if *useAES {
		cipherName = "AES-256-GCM"
	}
	memLabel := "4 GiB"
	if *lowMemory {
		memLabel = "64 MiB"
	}
	logger.Info("%s v%s  |  cipher=%s  Argon2id=%s/%d iter/%d threads",
		config.ProgramName, config.ProgramVersion,
		cipherName, memLabel, config.Argon2Time, config.Argon2Threads)

	// -----------------------------------------------------------------
	// Analyze (no password needed)
	// -----------------------------------------------------------------
	if *analyze {
		if err := fileproc.AnalyzeFile(*file, *debug); err != nil {
			logger.Error("%v", err)
			os.Exit(1)
		}
		return
	}

	// -----------------------------------------------------------------
	// Obtain password
	// -----------------------------------------------------------------
	password, err := resolvePassword(*passwordFlag, *passwordFile)
	if err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}
	if len(password) == 0 {
		logger.Error("password is empty")
		os.Exit(1)
	}
	if len(password) > config.MaxPasswordLen {
		logger.Warn("Password length (%d chars) exceeds recommended maximum (%d). Continuing anyway.",
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
		ShowProgress: !*noProgress,
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
			os.Exit(1)
		}
		return
	}

	// Single file mode.
	switch mode {
	case "encrypt":
		outDir := filepath.Join(filepath.Dir(*file), "encrypted")
		if _, err := fileproc.EncryptFile(*file, outDir, password, opts); err != nil {
			logger.Error("%v", err)
			os.Exit(1)
		}
	case "decrypt":
		outDir := filepath.Join(filepath.Dir(*file), "decrypted")
		if _, err := fileproc.DecryptFile(*file, outDir, password, opts); err != nil {
			logger.Error("%v", err)
			os.Exit(1)
		}
	}
}

// ---------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------

func validateFlags(encrypt, decrypt, analyze bool, folder, file, password, passwordFile string) error {
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

func resolvePassword(flagPass, flagFile string) ([]byte, error) {
	if flagPass != "" {
		return []byte(flagPass), nil
	}
	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			return nil, fmt.Errorf("read password file: %w", err)
		}
		return []byte(strings.TrimSpace(string(data))), nil
	}

	// Interactive prompt — read from terminal without echo.
	fmt.Fprint(os.Stderr, "Enter password: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("read password from terminal: %w", err)
	}
	return pass, nil
}
