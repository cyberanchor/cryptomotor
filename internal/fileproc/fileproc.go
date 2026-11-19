// Package fileproc implements file-level encrypt, decrypt, and analyze
// operations.  It assembles the system block, orchestrates streaming
// AEAD encryption, and verifies integrity on decryption.
//
// Key design principles:
//   - Streaming: payloads are never fully buffered in memory.
//   - Three independent nonces per file (payload, filename, hash).
//   - Encrypt-then-MAC: HMAC-SHA512 is computed over ciphertext.
//   - Partial outputs carry a temporary name and are removed on every error
//     path and, through Abort, on SIGINT/SIGTERM.
//   - A name stored in an encrypted file is used only if it is a plain file
//     name, and an existing file is never replaced without Options.Force.
package fileproc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cryptomotor/internal/config"
	"cryptomotor/internal/crypto"
	"cryptomotor/internal/logger"
	"cryptomotor/internal/sysmem"
)

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

var (
	ErrFilenameTooLong = errors.New("fileproc: filename exceeds maximum UTF-8 byte length")
	ErrBadSignature    = errors.New("fileproc: invalid file signature")
	ErrOldFormat       = errors.New("fileproc: file uses v2 format — not compatible with v3")
	ErrFileTooShort    = errors.New("fileproc: file is shorter than system block")
	ErrBadHeader       = errors.New("fileproc: corrupted or tampered system block")
	ErrUnsafeName      = errors.New("fileproc: stored file name is not a plain file name")
	ErrOutputExists    = errors.New("fileproc: output file already exists (use --force to replace it)")
	ErrNotRegular      = errors.New("fileproc: not a regular file")
	ErrNotEnoughMemory = errors.New("fileproc: not enough free memory for Argon2id with 4 GiB")
	ErrFolderFailures  = errors.New("fileproc: some files failed")
)

// Options controls per-operation behaviour.
type Options struct {
	CipherID     config.CipherID // Which AEAD to use (default: XChaCha20-Poly1305).
	LowMemory    bool            // Encrypt: Argon2id 64 MiB and 512 KiB chunks. Decrypt: only for files from 3.1.0 or earlier.
	Verbose      bool            // Print informational messages.
	Debug        bool            // Print system block dumps.
	DryRun       bool            // Simulate without writing anything.
	ShowProgress bool            // Render progress bars for large files.
	Force        bool            // Replace an existing output file.
}

// availableMemory is a variable so that tests can simulate small and large machines.
var availableMemory = sysmem.Available

// ---------------------------------------------------------------------
// Partial outputs
// ---------------------------------------------------------------------

var pending = struct {
	sync.Mutex
	files map[string]*os.File
}{files: map[string]*os.File{}}

func track(path string, f *os.File) {
	pending.Lock()
	pending.files[path] = f
	pending.Unlock()
}

func untrack(path string) {
	pending.Lock()
	delete(pending.files, path)
	pending.Unlock()
}

// discard closes and removes a partial output. The file is closed first:
// Windows cannot remove an open file.
func discard(path string) {
	pending.Lock()
	f := pending.files[path]
	delete(pending.files, path)
	pending.Unlock()
	if f != nil {
		f.Close()
	}
	os.Remove(path)
}

// Abort closes and removes every partial output file that is still being
// written and returns their paths. main calls it on SIGINT and SIGTERM.
func Abort() []string {
	pending.Lock()
	defer pending.Unlock()
	var removed []string
	for path, f := range pending.files {
		f.Close()
		if os.Remove(path) == nil {
			removed = append(removed, path)
		}
	}
	pending.files = map[string]*os.File{}
	return removed
}

// ---------------------------------------------------------------------
// Key derivation mode
// ---------------------------------------------------------------------

var fallbackWarned sync.Once

// chooseKDF picks the Argon2id cost for a new file: 64 MiB with --low-memory
// or when less than Argon2MemoryThreshold is free, 4 GiB otherwise. The
// choice is recorded in the file.
func chooseKDF(lowMemory bool) config.KDFMode {
	if lowMemory {
		return config.KDFLowMemory
	}
	avail, ok := availableMemory()
	slog.Debug("Free memory", "available_bytes", avail, "known", ok, "threshold_bytes", uint64(config.Argon2MemoryThreshold))
	if ok && avail < config.Argon2MemoryThreshold {
		fallbackWarned.Do(func() {
			logger.Warn("only %d MiB of RAM is free (less than %d MiB): using Argon2id with 64 MiB instead of 4 GiB. "+
				"The file records this, so decryption needs no flag.", avail>>20, uint64(config.Argon2MemoryThreshold)>>20)
		})
		return config.KDFLowMemory
	}
	return config.KDFStandard
}

// checkMemoryForStandard refuses a 4 GiB derivation that would not fit in RAM.
func checkMemoryForStandard() error {
	need := uint64(config.Argon2Memory)*1024 + config.Argon2MemoryHeadroom
	if avail, ok := availableMemory(); ok && avail < need {
		return fmt.Errorf("%w: it needs about %d MiB of free RAM, %d MiB are available",
			ErrNotEnoughMemory, need>>20, avail>>20)
	}
	return nil
}

// ---------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------

// EncryptFile encrypts inputPath and writes the result to outputDir.
// The output filename is a random hex string.
// Returns the path of the encrypted file.
//
// Single-pass architecture: the input file is read exactly once.
// During that single read, plaintext is simultaneously hashed (SHA-512)
// and encrypted.  Ciphertext is simultaneously written to disk and fed
// into the HMAC-SHA512 computation.  After the read loop finishes, the
// file hash and filename are encrypted (tiny in-memory operations), the
// HMAC is finalized, and the 810-byte header is patched in place.
//
//	inFile ─read─chunk─┬──→ sha512.Write(chunk)           → fileHash
//	                   └──→ aead.Seal(chunk) → ciphertext ─┬→ outFile.Write
//	                                                       └→ hmac.Write
//
// The output is written under a ".part" name and renamed when complete.
func EncryptFile(inputPath, outputDir string, password []byte, opts Options) (string, error) {
	start := time.Now()

	// --- cheap checks first: the key derivation is expensive -----------
	info, err := os.Stat(inputPath)
	if err != nil {
		return "", fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is a %s", ErrNotRegular, inputPath, fileKind(info.Mode()))
	}
	basename := filepath.Base(inputPath)
	nameBytes := []byte(basename)
	if len(nameBytes) > config.MaxFilenameBytes {
		return "", fmt.Errorf("%w: %d bytes", ErrFilenameTooLong, len(nameBytes))
	}
	if opts.CipherID.NonceSize() == 0 {
		return "", crypto.ErrInvalidCipher
	}

	outName := randomFilename()
	outPath := filepath.Join(outputDir, outName)
	if opts.DryRun {
		logger.Info("Dry run: would encrypt %s → %s", inputPath, outPath)
		return outPath, nil
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return "", fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	partPath := outPath + ".part"
	outFile, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}
	track(partPath, outFile)
	fail := func(err error) (string, error) {
		discard(partPath)
		return "", err
	}

	// --- derive key ----------------------------------------------------
	mode := chooseKDF(opts.LowMemory)
	chunkSize := config.ChunkSize
	if mode == config.KDFLowMemory {
		chunkSize = config.ChunkSizeLow
	}
	if opts.Verbose {
		logger.Info("Encrypting %s (%d bytes, cipher=%s, %s)", inputPath, info.Size(), opts.CipherID, mode)
	}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fail(err)
	}
	key := crypto.DeriveKey(password, salt, mode == config.KDFLowMemory)
	defer crypto.ZeroBytes(key)

	aead, err := crypto.NewAEAD(key, opts.CipherID)
	if err != nil {
		return fail(err)
	}

	// --- generate payload nonce ----------------------------------------
	noncePayload, err := crypto.GenerateNonce(aead)
	if err != nil {
		return fail(err)
	}

	// Write zeroed placeholder for the system block (patched after encryption).
	placeholder := make([]byte, config.SystemBlockLen)
	if _, err := outFile.Write(placeholder); err != nil {
		return fail(fmt.Errorf("write header placeholder: %w", err))
	}

	// --- single-pass: hash + encrypt + HMAC simultaneously -------------
	//
	// plainHasher: computes SHA-512 of the original plaintext.
	// hmacHasher:  computes HMAC-SHA512 of all bytes written after the header
	//              (chunk length prefixes + ciphertext + EOF sentinel).
	plainHasher := sha512.New()
	teeInput := io.TeeReader(inFile, plainHasher)

	hmacHasher := hmac.New(sha512.New, key)
	hmacHasher.Write(salt) // salt prefix, per HMAC protocol
	multiOutput := io.MultiWriter(outFile, hmacHasher)

	slog.Debug("EncryptFile single-pass started",
		"file", inputPath,
		"kdf", mode.String(),
		"chunk_size", chunkSize,
		"salt", hex.EncodeToString(salt),
		"nonce_payload", hex.EncodeToString(noncePayload),
	)

	if _, err = crypto.EncryptStream(aead, noncePayload, chunkSize, teeInput, multiOutput, opts.ShowProgress, info.Size()); err != nil {
		return fail(fmt.Errorf("single-pass encrypt: %w", err))
	}

	// --- post-loop: encrypt metadata and finalize HMAC -----------------
	fileHash := plainHasher.Sum(nil)

	// Encrypt filename (unique nonce).
	paddedName := make([]byte, config.PaddedFilenameLen)
	copy(paddedName, nameBytes)
	encFilename, nonceFilename, err := crypto.Seal(aead, paddedName)
	if err != nil {
		return fail(fmt.Errorf("encrypt filename: %w", err))
	}

	// Encrypt file hash (unique nonce).
	encHash, nonceHash, err := crypto.Seal(aead, fileHash)
	if err != nil {
		return fail(fmt.Errorf("encrypt hash: %w", err))
	}

	// Finalize HMAC: append encFilename and encHash, then compute digest.
	hmacHasher.Write(encFilename)
	hmacHasher.Write(encHash)
	hmacValue := hmacHasher.Sum(nil)

	slog.Debug("EncryptFile single-pass finished",
		"nonce_filename", hex.EncodeToString(nonceFilename),
		"nonce_hash", hex.EncodeToString(nonceHash),
		"hmac", hex.EncodeToString(hmacValue),
	)
	logger.Trace("Encrypted metadata",
		"original_name", basename,
		"original_name_hex", hex.EncodeToString(nameBytes),
		"file_sha512", hex.EncodeToString(fileHash),
	)

	// --- assemble and patch the system block ----------------------------
	header := buildSystemBlock(opts.CipherID, mode, salt,
		noncePayload, nonceFilename, nonceHash,
		hmacValue, encFilename, encHash, uint32(len(nameBytes)))

	if _, err := outFile.Seek(0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("seek for header: %w", err))
	}
	if _, err := outFile.Write(header); err != nil {
		return fail(fmt.Errorf("write header: %w", err))
	}

	// Flush all data (including the patched header) to persistent storage.
	// Without this, a power loss right after "success" could leave the file
	// with a zeroed header on disk — making it permanently unrecoverable.
	if err := outFile.Sync(); err != nil {
		return fail(fmt.Errorf("sync output: %w", err))
	}
	if err := outFile.Close(); err != nil {
		return fail(fmt.Errorf("close output: %w", err))
	}
	if err := os.Rename(partPath, outPath); err != nil {
		return fail(fmt.Errorf("rename output: %w", err))
	}
	untrack(partPath)

	if opts.Debug {
		printDebugBlock("Encrypted", outPath, header)
	}
	if logger.TraceEnabled() {
		logger.Trace("System block", "path", outPath, "hex", hex.EncodeToString(header))
	}
	logger.Success("Encrypted %s → %s in %s", inputPath, outPath, time.Since(start).Truncate(time.Millisecond))
	return outPath, nil
}

// ---------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------

// DecryptFile decrypts an encrypted file and writes the original to outputDir.
// Returns the path of the decrypted file.
func DecryptFile(encPath, outputDir string, password []byte, opts Options) (string, error) {
	start := time.Now()

	// --- read and parse system block -----------------------------------
	hdr, err := readSystemBlock(encPath)
	if err != nil {
		return "", err
	}

	if opts.Debug {
		printDebugBlock("Decrypting", encPath, hdr.raw)
	}
	if opts.Verbose {
		logger.Info("Decrypting %s (cipher=%s, key derivation: %s)", encPath, hdr.cipherID, hdr.kdf)
	}
	if logger.TraceEnabled() {
		logger.Trace("System block", "path", encPath, "hex", hex.EncodeToString(hdr.raw))
	}

	// --- derive key and verify HMAC before any decryption ---------------
	key, err := deriveForFile(encPath, hdr, password, opts)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(key)

	// --- construct AEAD ------------------------------------------------
	aead, err := crypto.NewAEAD(key, hdr.cipherID)
	if err != nil {
		return "", err
	}

	// --- decrypt filename and hash -------------------------------------
	paddedName, err := crypto.Open(aead, hdr.nonceFilename, hdr.encFilename)
	if err != nil {
		return "", fmt.Errorf("decrypt filename: %w", err)
	}
	// File names cannot contain NUL, so the name ends at the first zero byte.
	// This cross-checks the unauthenticated OrigNameLen field.
	nameLen := bytes.IndexByte(paddedName, 0)
	if nameLen < 0 {
		nameLen = len(paddedName)
	}
	if uint32(nameLen) != hdr.origNameLen || bytes.ContainsFunc(paddedName[nameLen:], func(r rune) bool { return r != 0 }) {
		return "", fmt.Errorf("%w: the name length field says %d bytes, the encrypted name has %d",
			ErrBadHeader, hdr.origNameLen, nameLen)
	}
	originalName := string(paddedName[:nameLen])
	logger.Trace("Decrypted name", "original_name", originalName, "padded_name_hex", hex.EncodeToString(paddedName[:nameLen]))
	if err := checkStoredName(originalName); err != nil {
		return "", err
	}

	fileHash, err := crypto.Open(aead, hdr.nonceHash, hdr.encHash)
	if err != nil {
		return "", fmt.Errorf("decrypt hash: %w", err)
	}
	logger.Trace("Decrypted hash", "file_sha512", hex.EncodeToString(fileHash))

	finalPath := filepath.Join(outputDir, originalName)
	_, statErr := os.Lstat(finalPath)
	exists := statErr == nil
	if opts.DryRun {
		if exists && !opts.Force {
			logger.Warn("Dry run: %s already exists; decrypting would fail without --force", finalPath)
		}
		logger.Info("Dry run: would decrypt %s → %s", encPath, finalPath)
		return finalPath, nil
	}
	if exists && !opts.Force {
		return "", fmt.Errorf("%w: %s", ErrOutputExists, finalPath)
	}

	// --- stream-decrypt payload into temp file -------------------------
	encFile, err := os.Open(encPath)
	if err != nil {
		return "", fmt.Errorf("open encrypted: %w", err)
	}
	defer encFile.Close()
	encInfo, err := encFile.Stat()
	if err != nil {
		return "", fmt.Errorf("stat encrypted: %w", err)
	}
	if _, err := encFile.Seek(int64(config.SystemBlockLen), io.SeekStart); err != nil {
		return "", fmt.Errorf("seek past header: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	tempPath := filepath.Join(outputDir, randomFilename()+".tmp")
	tmpFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	track(tempPath, tmpFile)
	fail := func(err error) (string, error) {
		discard(tempPath)
		return "", err
	}

	// The SHA-512 is computed while writing: reading the file back would
	// only read the page cache again.
	hasher := sha512.New()
	payloadSize := encInfo.Size() - int64(config.SystemBlockLen)
	if _, err := crypto.DecryptStream(aead, hdr.noncePayload, encFile, io.MultiWriter(tmpFile, hasher), opts.ShowProgress, payloadSize); err != nil {
		return fail(fmt.Errorf("stream decrypt: %w", err))
	}
	computed := hasher.Sum(nil)
	logger.Trace("Plaintext hash", "computed_sha512", hex.EncodeToString(computed), "match", hmac.Equal(computed, fileHash))
	if !hmac.Equal(computed, fileHash) {
		return fail(crypto.ErrFileHashMismatch)
	}
	if err := tmpFile.Sync(); err != nil {
		return fail(fmt.Errorf("sync output: %w", err))
	}
	if err := tmpFile.Close(); err != nil {
		return fail(fmt.Errorf("close output: %w", err))
	}

	// --- move to the original name -------------------------------------
	if err := publish(tempPath, finalPath, opts.Force); err != nil {
		return fail(fmt.Errorf("rename to final: %w", err))
	}
	untrack(tempPath)

	logger.Success("Decrypted %s → %s in %s", encPath, finalPath, time.Since(start).Truncate(time.Millisecond))
	return finalPath, nil
}

// deriveForFile derives the key for an encrypted file and verifies the file's
// HMAC with it. Files from 3.2.0 on record their Argon2id cost. Files from
// 3.1.0 and earlier do not: they are tried with 64 MiB first (cheap), then
// with 4 GiB, unless --low-memory says the file used 64 MiB.
func deriveForFile(path string, hdr *systemBlock, password []byte, opts Options) ([]byte, error) {
	var modes []config.KDFMode
	switch hdr.kdf {
	case config.KDFLowMemory, config.KDFStandard:
		modes = []config.KDFMode{hdr.kdf}
	default:
		modes = []config.KDFMode{config.KDFLowMemory}
		if !opts.LowMemory {
			modes = append(modes, config.KDFStandard)
		}
	}

	var memErr error
	for _, mode := range modes {
		if mode == config.KDFStandard {
			if memErr = checkMemoryForStandard(); memErr != nil {
				break
			}
		}
		key := crypto.DeriveKey(password, hdr.salt, mode == config.KDFLowMemory)
		err := verifyFileHMAC(path, key, hdr)
		if err == nil {
			slog.Debug("HMAC verified", "file", path, "kdf", mode.String())
			return key, nil
		}
		crypto.ZeroBytes(key)
		if !errors.Is(err, crypto.ErrHMACMismatch) {
			return nil, err
		}
		slog.Debug("HMAC mismatch", "file", path, "kdf", mode.String())
	}

	switch {
	case memErr != nil && hdr.kdf == config.KDFStandard:
		return nil, fmt.Errorf("%s was encrypted with Argon2id 4 GiB: %w", path, memErr)
	case memErr != nil:
		return nil, fmt.Errorf("%w with Argon2id 64 MiB; the 4 GiB setting (files encrypted without --low-memory by 3.1.0 or earlier) cannot be tried: %v",
			crypto.ErrHMACMismatch, memErr)
	}
	return nil, crypto.ErrHMACMismatch
}

// verifyFileHMAC streams everything after the header through HMAC-SHA512.
func verifyFileHMAC(path string, key []byte, hdr *systemBlock) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for HMAC verification: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(int64(config.SystemBlockLen), io.SeekStart); err != nil {
		return fmt.Errorf("seek for HMAC verification: %w", err)
	}
	return crypto.VerifyHMACStream(key, hdr.salt, hdr.hmac, f, hdr.encFilename, hdr.encHash)
}

// checkStoredName rejects a name taken from an encrypted file unless it is a
// single file name inside the output directory on this system: not empty,
// "." or "..", without NUL or a path separator, and (on Windows) not a
// reserved device name or a drive-relative path. Anyone who knows the
// password can store any name, so this is what keeps "../../.bashrc" out.
func checkStoredName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, 0) ||
		strings.ContainsRune(name, '/') || filepath.Base(name) != name || !filepath.IsLocal(name) {
		return fmt.Errorf("%w: %q", ErrUnsafeName, name)
	}
	return nil
}

// publish moves the finished temp file to its final name. Without force an
// existing file, directory or symlink at that name is never replaced.
func publish(tmp, final string, force bool) error {
	if force {
		return os.Rename(tmp, final)
	}
	// A hard link fails instead of replacing: atomic and race-free.
	err := os.Link(tmp, final)
	if err == nil {
		return os.Remove(tmp)
	}
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s", ErrOutputExists, final)
	}
	// File systems without hard links (FAT, some network shares): reserve
	// the name with O_EXCL, then rename over the reservation.
	f, err := os.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrOutputExists, final)
		}
		return err
	}
	f.Close()
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(final)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------
// Analyze
// ---------------------------------------------------------------------

// AnalyzeFile prints a breakdown of the system block. It needs no password.
func AnalyzeFile(path string, debug bool) error {
	hdr, err := readSystemBlock(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	payloadSize := info.Size() - int64(config.SystemBlockLen)

	fmt.Printf("Analysis of %s:\n", logger.Clean(path))
	fmt.Printf("  File size:      %d bytes\n", info.Size())
	fmt.Printf("  System block:   %d bytes\n", config.SystemBlockLen)
	fmt.Printf("  Cipher:         %s\n", hdr.cipherID)
	fmt.Printf("  Key derivation: %s\n", hdr.kdf)
	fmt.Printf("  Payload:        %d bytes (encrypted)\n", payloadSize)
	fmt.Println()

	if debug {
		printDebugBlock("Analysis", path, hdr.raw)
	}
	if logger.TraceEnabled() {
		logger.Trace("System block", "path", path, "hex", hex.EncodeToString(hdr.raw))
	}
	return nil
}

// ---------------------------------------------------------------------
// System block builder
// ---------------------------------------------------------------------

func buildSystemBlock(
	cipherID config.CipherID,
	kdf config.KDFMode,
	salt []byte,
	noncePayload, nonceFilename, nonceHash []byte,
	hmacValue []byte,
	encFilename, encHash []byte,
	origNameLen uint32,
) []byte {
	buf := make([]byte, config.SystemBlockLen)

	off := 0

	// Signature (8 bytes).
	copy(buf[off:], config.Signature)
	off += config.SignatureLen

	// CipherID (1 byte).
	buf[off] = byte(cipherID)
	off += config.CipherIDLen

	// KDF mode (1 byte).
	buf[off] = byte(kdf)
	off += config.KDFModeLen

	// Salt (64 bytes).
	copy(buf[off:], salt)
	off += config.SaltLen

	// Nonce fields (3 × 24 bytes). Each nonce is right-aligned.
	np := crypto.EncodeNonce(noncePayload)
	copy(buf[off:], np[:])
	off += config.NonceFieldLen

	nf := crypto.EncodeNonce(nonceFilename)
	copy(buf[off:], nf[:])
	off += config.NonceFieldLen

	nh := crypto.EncodeNonce(nonceHash)
	copy(buf[off:], nh[:])
	off += config.NonceFieldLen

	// HMAC-SHA512 (64 bytes).
	copy(buf[off:], hmacValue)
	off += config.HMACLen

	// Padded filename length (4 bytes, big-endian).
	binary.BigEndian.PutUint32(buf[off:], uint32(config.PaddedFilenameLen))
	off += config.FilenameLenField

	// Encrypted filename (512 bytes).
	copy(buf[off:], encFilename)
	off += config.EncFilenameLen

	// Encrypted hash (80 bytes).
	copy(buf[off:], encHash)
	off += config.EncHashLen

	// Original filename length (4 bytes, big-endian).
	binary.BigEndian.PutUint32(buf[off:], origNameLen)

	return buf
}

// ---------------------------------------------------------------------
// System block parser
// ---------------------------------------------------------------------

type systemBlock struct {
	raw           []byte
	cipherID      config.CipherID
	kdf           config.KDFMode
	salt          []byte
	noncePayload  []byte
	nonceFilename []byte
	nonceHash     []byte
	hmac          []byte
	encFilename   []byte
	encHash       []byte
	origNameLen   uint32
}

func readSystemBlock(path string) (*systemBlock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open for header: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat for header: %w", err)
	}
	if info.Size() < int64(config.SystemBlockLen) {
		return nil, fmt.Errorf("%w: %d bytes", ErrFileTooShort, info.Size())
	}

	raw := make([]byte, config.SystemBlockLen)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Check signature.
	sig := string(raw[:config.SignatureLen])
	if sig == config.OldSignature {
		return nil, ErrOldFormat
	}
	if sig != config.Signature {
		return nil, fmt.Errorf("%w: got %q", ErrBadSignature, sig)
	}

	o := config.SystemBlockOffsets
	cipherID := config.CipherID(raw[o.CipherID])
	if cipherID != config.CipherAES256GCM && cipherID != config.CipherChaCha20Poly1305 {
		return nil, fmt.Errorf("%w: unknown cipher ID 0x%02x", ErrBadHeader, byte(cipherID))
	}
	kdf := config.KDFMode(raw[o.KDFMode])
	if !kdf.Valid() {
		return nil, fmt.Errorf("%w: unknown key derivation mode 0x%02x (written by a newer version?)", ErrBadHeader, byte(kdf))
	}
	if v := binary.BigEndian.Uint32(raw[o.FilenameLen:]); v != config.PaddedFilenameLen {
		return nil, fmt.Errorf("%w: padded name length field is %d, not %d", ErrBadHeader, v, config.PaddedFilenameLen)
	}
	unused := config.NonceFieldLen - cipherID.NonceSize()
	for _, field := range []int{o.NoncePayload, o.NonceFilename, o.NonceHash} {
		if bytes.ContainsFunc(raw[field:field+unused], func(r rune) bool { return r != 0 }) {
			return nil, fmt.Errorf("%w: unused nonce bytes at offset %d are not zero", ErrBadHeader, field)
		}
	}
	origNameLen := binary.BigEndian.Uint32(raw[o.OrigNameLen : o.OrigNameLen+config.OrigNameLenField])
	if origNameLen > config.PaddedFilenameLen {
		return nil, fmt.Errorf("%w: name length field is %d (at most %d)", ErrBadHeader, origNameLen, config.PaddedFilenameLen)
	}

	hdr := &systemBlock{
		raw:           raw,
		cipherID:      cipherID,
		kdf:           kdf,
		salt:          raw[o.Salt : o.Salt+config.SaltLen],
		noncePayload:  crypto.DecodeNonce(raw[o.NoncePayload:o.NoncePayload+config.NonceFieldLen], cipherID),
		nonceFilename: crypto.DecodeNonce(raw[o.NonceFilename:o.NonceFilename+config.NonceFieldLen], cipherID),
		nonceHash:     crypto.DecodeNonce(raw[o.NonceHash:o.NonceHash+config.NonceFieldLen], cipherID),
		hmac:          raw[o.HMAC : o.HMAC+config.HMACLen],
		encFilename:   raw[o.EncFilename : o.EncFilename+config.EncFilenameLen],
		encHash:       raw[o.EncHash : o.EncHash+config.EncHashLen],
		origNameLen:   origNameLen,
	}
	return hdr, nil
}

// ---------------------------------------------------------------------
// Folder processing
// ---------------------------------------------------------------------

// ProcessFolder encrypts or decrypts every regular file directly inside a
// folder (subfolders are not processed). mode must be "encrypt" or
// "decrypt". It returns an error wrapping ErrFolderFailures when any file
// failed.
func ProcessFolder(folder string, password []byte, mode string, opts Options) error {
	if mode != "encrypt" && mode != "decrypt" {
		return fmt.Errorf("unknown mode %q", mode)
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		return fmt.Errorf("read directory: %w", err)
	}

	subdir := "encrypted"
	if mode == "decrypt" {
		subdir = "decrypted"
	}
	outDir := filepath.Join(folder, subdir)

	var processed, skipped, failed int
	start := time.Now()
	skip := func(path, why string) {
		if opts.Verbose {
			logger.Warn("Skipping %s: %s", path, why)
		}
		skipped++
	}

	for _, entry := range entries {
		path := filepath.Join(folder, entry.Name())
		if entry.IsDir() {
			continue
		}
		info, err := os.Stat(path) // follows symlinks
		if err != nil {
			logger.Error("%s %s: %v", mode, path, err)
			failed++
			continue
		}
		if info.IsDir() {
			continue // a symlink to a directory counts as a directory
		}
		if !info.Mode().IsRegular() {
			// Opening a named pipe would block; devices and sockets are not files to encrypt.
			skip(path, "not a regular file ("+fileKind(info.Mode())+")")
			continue
		}

		switch mode {
		case "encrypt":
			if _, err := EncryptFile(path, outDir, password, opts); err != nil {
				logger.Error("encrypt %s: %v", path, err)
				failed++
			} else {
				processed++
			}

		case "decrypt":
			// Quick signature check before attempting full decryption.
			sig, sigErr := peekSignature(path)
			switch {
			case sigErr == nil && sig == config.Signature:
			case sigErr == nil, errors.Is(sigErr, io.EOF), errors.Is(sigErr, io.ErrUnexpectedEOF):
				skip(path, "not a cryptomotor v3 file")
				continue
			default: // unreadable: a failure, not a foreign file
				logger.Error("decrypt %s: %v", path, sigErr)
				failed++
				continue
			}
			if _, err := DecryptFile(path, outDir, password, opts); err != nil {
				logger.Error("decrypt %s: %v", path, err)
				failed++
			} else {
				processed++
			}
		}
	}

	elapsed := time.Since(start)
	logger.Info("Completed %s in %s: %d processed, %d skipped, %d failed (%.1fs)",
		mode, folder, processed, skipped, failed, elapsed.Seconds())
	if failed > 0 {
		return fmt.Errorf("%w: %d of %d", ErrFolderFailures, failed, processed+failed)
	}
	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// randomFilename generates a random hex string of RandomFilenameLen characters.
func randomFilename() string {
	b := make([]byte, config.RandomFilenameLen/2)
	if _, err := rand.Read(b); err != nil {
		panic("randomFilename: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// fileKind names the type of a non-regular file for messages.
func fileKind(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "directory"
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	default:
		return "special file"
	}
}

// peekSignature reads the first SignatureLen bytes from a file.
func peekSignature(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, config.SignatureLen)
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// printDebugBlock dumps the system block fields. All of them are stored in
// the file in clear text; --trace adds the full hex dump.
func printDebugBlock(label, path string, raw []byte) {
	o := config.SystemBlockOffsets
	fmt.Printf("\n%s — system block for %s:\n", label, logger.Clean(path))
	fmt.Printf("  Signature:       %s\n", strings.TrimRight(string(raw[:config.SignatureLen]), "\x00"))
	fmt.Printf("  CipherID:        0x%02x (%s)\n", raw[o.CipherID], config.CipherID(raw[o.CipherID]))
	fmt.Printf("  KDF mode:        0x%02x (%s)\n", raw[o.KDFMode], config.KDFMode(raw[o.KDFMode]))
	fmt.Printf("  Salt:            %s…\n", hex.EncodeToString(raw[o.Salt:o.Salt+16]))
	fmt.Printf("  Nonce(payload):  %s\n", hex.EncodeToString(raw[o.NoncePayload:o.NoncePayload+config.NonceFieldLen]))
	fmt.Printf("  Nonce(filename): %s\n", hex.EncodeToString(raw[o.NonceFilename:o.NonceFilename+config.NonceFieldLen]))
	fmt.Printf("  Nonce(hash):     %s\n", hex.EncodeToString(raw[o.NonceHash:o.NonceHash+config.NonceFieldLen]))
	fmt.Printf("  HMAC-SHA512:     %s…\n", hex.EncodeToString(raw[o.HMAC:o.HMAC+16]))
	fnLen := binary.BigEndian.Uint32(raw[o.FilenameLen : o.FilenameLen+4])
	fmt.Printf("  Padded name len: %d\n", fnLen)
	fmt.Printf("  Enc filename:    %s…\n", hex.EncodeToString(raw[o.EncFilename:o.EncFilename+16]))
	fmt.Printf("  Enc hash:        %s…\n", hex.EncodeToString(raw[o.EncHash:o.EncHash+16]))
	origLen := binary.BigEndian.Uint32(raw[o.OrigNameLen : o.OrigNameLen+4])
	fmt.Printf("  Orig name len:   %d bytes\n\n", origLen)
}
