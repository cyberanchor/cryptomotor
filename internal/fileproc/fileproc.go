// Package fileproc implements file-level encrypt, decrypt, and analyze
// operations.  It assembles the system block, orchestrates streaming
// AEAD encryption, and verifies integrity on decryption.
//
// Key design principles:
//   - Streaming: payloads are never fully buffered in memory.
//   - Three independent nonces per file (payload, filename, hash).
//   - Encrypt-then-MAC: HMAC-SHA512 is computed over ciphertext.
//   - Temporary files are cleaned up on any error path.
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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cryptomotor/internal/config"
	"cryptomotor/internal/crypto"
	"cryptomotor/internal/logger"
)

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

var (
	ErrFileTooSmall   = errors.New("fileproc: file is smaller than minimum size")
	ErrFilenameTooLong = errors.New("fileproc: filename exceeds maximum UTF-8 byte length")
	ErrBadSignature   = errors.New("fileproc: invalid file signature")
	ErrOldFormat      = errors.New("fileproc: file uses v2 format — not compatible with v3")
	ErrFileTooShort   = errors.New("fileproc: file is shorter than system block")
)

// Options controls per-operation behaviour.
type Options struct {
	CipherID    config.CipherID // Which AEAD to use (default: XChaCha20-Poly1305).
	LowMemory   bool            // Reduce Argon2id memory cost to 64 MiB.
	Verbose     bool            // Print informational messages.
	Debug       bool            // Print system block hex dumps.
	DryRun      bool            // Simulate without writing output files.
	ShowProgress bool           // Render progress bars for large files.
}

// DefaultOptions returns sensible defaults for interactive CLI use.
func DefaultOptions() Options {
	return Options{
		CipherID:     config.CipherChaCha20Poly1305,
		ShowProgress: true,
	}
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
func EncryptFile(inputPath, outputDir string, password []byte, opts Options) (string, error) {
	start := time.Now()

	// --- validate input ------------------------------------------------
	info, err := os.Stat(inputPath)
	if err != nil {
		return "", fmt.Errorf("stat input: %w", err)
	}
	if info.Size() < config.MinFileSize {
		return "", fmt.Errorf("%w: %d bytes", ErrFileTooSmall, info.Size())
	}
	basename := filepath.Base(inputPath)
	nameBytes := []byte(basename)
	if len(nameBytes) > config.MaxFilenameBytes {
		return "", fmt.Errorf("%w: %d bytes", ErrFilenameTooLong, len(nameBytes))
	}

	if opts.Verbose {
		logger.Info("Encrypting %s (%d bytes, cipher=%s)", inputPath, info.Size(), opts.CipherID)
	}

	// --- derive key ----------------------------------------------------
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return "", err
	}
	key := crypto.DeriveKey(password, salt, opts.LowMemory)
	defer crypto.ZeroBytes(key)

	aead, err := crypto.NewAEAD(key, opts.CipherID)
	if err != nil {
		return "", err
	}

	// --- generate payload nonce ----------------------------------------
	noncePayload, err := crypto.GenerateNonce(aead)
	if err != nil {
		return "", err
	}

	// --- prepare output file -------------------------------------------
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	outName := randomFilename()
	outPath := filepath.Join(outputDir, outName)

	if opts.DryRun {
		logger.Info("Dry run: would encrypt %s → %s", inputPath, outPath)
		return outPath, nil
	}

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()

	// Write zeroed placeholder for the system block (patched after encryption).
	placeholder := make([]byte, config.SystemBlockLen)
	if _, err := outFile.Write(placeholder); err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("write header placeholder: %w", err)
	}

	// --- open input file -----------------------------------------------
	inFile, err := os.Open(inputPath)
	if err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	// --- single-pass: hash + encrypt + HMAC simultaneously -------------
	//
	// plainHasher: computes SHA-512 of the original plaintext.
	// hmacHasher:  computes HMAC-SHA512 of all bytes written after the header
	//              (chunk length prefixes + ciphertext + EOF sentinel).
	//
	// teeInput reads from inFile and duplicates every byte into plainHasher.
	// multiOutput writes to both outFile and hmacHasher simultaneously.
	plainHasher := sha512.New()
	teeInput := io.TeeReader(inFile, plainHasher)

	hmacHasher := hmac.New(sha512.New, key)
	hmacHasher.Write(salt) // salt prefix, per HMAC protocol
	multiOutput := io.MultiWriter(outFile, hmacHasher)

	slog.Debug("EncryptFile single-pass started",
		"file", inputPath,
		"salt", hex.EncodeToString(salt),
		"nonce_payload", hex.EncodeToString(noncePayload),
	)

	_, err = crypto.EncryptStream(aead, noncePayload, teeInput, multiOutput, opts.ShowProgress, info.Size())
	if err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("single-pass encrypt: %w", err)
	}

	// --- post-loop: encrypt metadata and finalize HMAC -----------------
	// At this point plainHasher has the full SHA-512 of the original file,
	// and hmacHasher has consumed all ciphertext bytes (including framing).
	fileHash := plainHasher.Sum(nil)

	// Encrypt filename (unique nonce).
	paddedName := make([]byte, config.PaddedFilenameLen)
	copy(paddedName, nameBytes)
	encFilename, nonceFilename, err := crypto.Seal(aead, paddedName)
	if err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("encrypt filename: %w", err)
	}

	// Encrypt file hash (unique nonce).
	encHash, nonceHash, err := crypto.Seal(aead, fileHash)
	if err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("encrypt hash: %w", err)
	}

	// Finalize HMAC: append encFilename and encHash, then compute digest.
	hmacHasher.Write(encFilename)
	hmacHasher.Write(encHash)
	hmacValue := hmacHasher.Sum(nil)

	slog.Debug("EncryptFile single-pass finished",
		"file_hash", hex.EncodeToString(fileHash),
		"nonce_filename", hex.EncodeToString(nonceFilename),
		"nonce_hash", hex.EncodeToString(nonceHash),
		"hmac", hex.EncodeToString(hmacValue),
		"original_name", basename,
	)

	// --- assemble and patch the system block ----------------------------
	header := buildSystemBlock(opts.CipherID, salt,
		noncePayload, nonceFilename, nonceHash,
		hmacValue, encFilename, encHash, uint32(len(nameBytes)))

	if _, err := outFile.Seek(0, io.SeekStart); err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("seek for header: %w", err)
	}
	if _, err := outFile.Write(header); err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("write header: %w", err)
	}

	// Flush all data (including the patched header) to persistent storage.
	// Without this, a power loss right after "success" could leave the file
	// with a zeroed header on disk — making it permanently unrecoverable.
	if err := outFile.Sync(); err != nil {
		os.Remove(outPath)
		return "", fmt.Errorf("sync output: %w", err)
	}

	elapsed := time.Since(start)
	if opts.Debug {
		printDebugBlock("Encrypted", outPath, header)
	}
	logger.Success("Encrypted %s → %s in %s", inputPath, outPath, elapsed.Truncate(time.Millisecond))
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
		logger.Info("Decrypting %s (cipher=%s)", encPath, hdr.cipherID)
	}

	// --- derive key ----------------------------------------------------
	key := crypto.DeriveKey(password, hdr.salt, opts.LowMemory)
	defer crypto.ZeroBytes(key)

	slog.Debug("DecryptFile parsed header",
		"file", encPath,
		"cipher", hdr.cipherID.String(),
		"salt", hex.EncodeToString(hdr.salt),
		"nonce_payload", hex.EncodeToString(hdr.noncePayload),
		"nonce_filename", hex.EncodeToString(hdr.nonceFilename),
		"nonce_hash", hex.EncodeToString(hdr.nonceHash),
		"stored_hmac", hex.EncodeToString(hdr.hmac),
		"orig_name_len", hdr.origNameLen,
	)

	// --- verify HMAC (Encrypt-then-MAC, streaming) before any decryption -
	hmacReader, err := os.Open(encPath)
	if err != nil {
		return "", fmt.Errorf("open for HMAC verification: %w", err)
	}
	if _, err := hmacReader.Seek(int64(config.SystemBlockLen), io.SeekStart); err != nil {
		hmacReader.Close()
		return "", fmt.Errorf("seek for HMAC verification: %w", err)
	}
	hmacErr := crypto.VerifyHMACStream(key, hdr.salt, hdr.hmac, hmacReader, hdr.encFilename, hdr.encHash)
	hmacReader.Close()
	if hmacErr != nil {
		return "", hmacErr
	}

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
	originalName := string(paddedName[:hdr.origNameLen])

	fileHash, err := crypto.Open(aead, hdr.nonceHash, hdr.encHash)
	if err != nil {
		return "", fmt.Errorf("decrypt hash: %w", err)
	}

	slog.Debug("Decrypted metadata",
		"original_name", originalName,
		"file_hash", hex.EncodeToString(fileHash),
	)

	// --- stream-decrypt payload into temp file -------------------------
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	tempPath := filepath.Join(outputDir, randomFilename()+".tmp")
	if opts.DryRun {
		logger.Info("Dry run: would decrypt %s → %s/%s", encPath, outputDir, originalName)
		return filepath.Join(outputDir, originalName), nil
	}

	encFile, err := os.Open(encPath)
	if err != nil {
		return "", fmt.Errorf("open encrypted: %w", err)
	}
	defer encFile.Close()

	// Skip past system block.
	if _, err := encFile.Seek(int64(config.SystemBlockLen), io.SeekStart); err != nil {
		return "", fmt.Errorf("seek past header: %w", err)
	}

	tmpFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}

	encInfo, _ := os.Stat(encPath)
	payloadSize := encInfo.Size() - int64(config.SystemBlockLen)

	_, err = crypto.DecryptStream(aead, hdr.noncePayload, encFile, tmpFile, opts.ShowProgress, payloadSize)
	tmpFile.Close()
	if err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("stream decrypt: %w", err)
	}

	// --- verify file hash ----------------------------------------------
	computedHash, err := crypto.HashFile(tempPath, config.BufferSize, opts.ShowProgress)
	if err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("hash decrypted: %w", err)
	}
	if !bytes.Equal(computedHash, fileHash) {
		os.Remove(tempPath)
		return "", crypto.ErrFileHashMismatch
	}

	// --- rename to original filename -----------------------------------
	finalPath := filepath.Join(outputDir, originalName)
	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("rename to final: %w", err)
	}

	elapsed := time.Since(start)
	logger.Success("Decrypted %s → %s in %s", encPath, finalPath, elapsed.Truncate(time.Millisecond))
	return finalPath, nil
}

// ---------------------------------------------------------------------
// Analyze
// ---------------------------------------------------------------------

// AnalyzeFile prints a detailed breakdown of the system block.
func AnalyzeFile(path string, debug bool) error {
	hdr, err := readSystemBlock(path)
	if err != nil {
		return err
	}

	info, _ := os.Stat(path)
	payloadSize := info.Size() - int64(config.SystemBlockLen)

	fmt.Printf("Analysis of %s:\n", path)
	fmt.Printf("  File size:      %d bytes\n", info.Size())
	fmt.Printf("  System block:   %d bytes\n", config.SystemBlockLen)
	fmt.Printf("  Cipher:         %s\n", hdr.cipherID)
	fmt.Printf("  Payload:        %d bytes (encrypted)\n", payloadSize)
	fmt.Printf("  Original name:  %d bytes\n", hdr.origNameLen)
	fmt.Println()

	if debug {
		printDebugBlock("Analysis", path, hdr.raw)
	}
	return nil
}

// ---------------------------------------------------------------------
// System block builder
// ---------------------------------------------------------------------

func buildSystemBlock(
	cipherID config.CipherID,
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

	// Reserved (1 byte, zero).
	off += config.ReservedLen

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

	// Encrypted filename length (4 bytes, big-endian).
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
		return nil, fmt.Errorf("unknown cipher ID: 0x%02x", cipherID)
	}

	hdr := &systemBlock{
		raw:           raw,
		cipherID:      cipherID,
		salt:          raw[o.Salt : o.Salt+config.SaltLen],
		noncePayload:  crypto.DecodeNonce(raw[o.NoncePayload:o.NoncePayload+config.NonceFieldLen], cipherID),
		nonceFilename: crypto.DecodeNonce(raw[o.NonceFilename:o.NonceFilename+config.NonceFieldLen], cipherID),
		nonceHash:     crypto.DecodeNonce(raw[o.NonceHash:o.NonceHash+config.NonceFieldLen], cipherID),
		hmac:          raw[o.HMAC : o.HMAC+config.HMACLen],
		encFilename:   raw[o.EncFilename : o.EncFilename+config.EncFilenameLen],
		encHash:       raw[o.EncHash : o.EncHash+config.EncHashLen],
		origNameLen:   binary.BigEndian.Uint32(raw[o.OrigNameLen : o.OrigNameLen+config.OrigNameLenField]),
	}
	return hdr, nil
}

// ---------------------------------------------------------------------
// Folder processing
// ---------------------------------------------------------------------

// ProcessFolder encrypts or decrypts every applicable file in a folder.
// mode must be "encrypt" or "decrypt".
func ProcessFolder(folder string, password []byte, mode string, opts Options) error {
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

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(folder, entry.Name())

		switch mode {
		case "encrypt":
			_, err := EncryptFile(path, outDir, password, opts)
			if err != nil {
				logger.Error("encrypt %s: %v", path, err)
				failed++
			} else {
				processed++
			}

		case "decrypt":
			// Quick signature check before attempting full decryption.
			sig, sigErr := peekSignature(path)
			if sigErr != nil || sig != config.Signature {
				if opts.Verbose {
					logger.Warn("Skipping %s: not a cryptomotor v3 file", path)
				}
				skipped++
				continue
			}
			_, err := DecryptFile(path, outDir, password, opts)
			if err != nil {
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

// printDebugBlock dumps a hex representation of the system block fields.
func printDebugBlock(label, path string, raw []byte) {
	o := config.SystemBlockOffsets
	fmt.Printf("\n%s — system block for %s:\n", label, path)
	fmt.Printf("  Signature:       %s\n", strings.TrimRight(string(raw[:config.SignatureLen]), "\x00"))
	fmt.Printf("  CipherID:        0x%02x (%s)\n", raw[o.CipherID], config.CipherID(raw[o.CipherID]))
	fmt.Printf("  Salt:            %s…\n", hex.EncodeToString(raw[o.Salt:o.Salt+16]))
	fmt.Printf("  Nonce(payload):  %s\n", hex.EncodeToString(raw[o.NoncePayload:o.NoncePayload+config.NonceFieldLen]))
	fmt.Printf("  Nonce(filename): %s\n", hex.EncodeToString(raw[o.NonceFilename:o.NonceFilename+config.NonceFieldLen]))
	fmt.Printf("  Nonce(hash):     %s\n", hex.EncodeToString(raw[o.NonceHash:o.NonceHash+config.NonceFieldLen]))
	fmt.Printf("  HMAC-SHA512:     %s…\n", hex.EncodeToString(raw[o.HMAC:o.HMAC+16]))
	fnLen := binary.BigEndian.Uint32(raw[o.FilenameLen : o.FilenameLen+4])
	fmt.Printf("  Enc filename len: %d\n", fnLen)
	fmt.Printf("  Enc filename:    %s…\n", hex.EncodeToString(raw[o.EncFilename:o.EncFilename+16]))
	fmt.Printf("  Enc hash:        %s…\n", hex.EncodeToString(raw[o.EncHash:o.EncHash+16]))
	origLen := binary.BigEndian.Uint32(raw[o.OrigNameLen : o.OrigNameLen+4])
	fmt.Printf("  Orig name len:   %d bytes\n\n", origLen)
}
