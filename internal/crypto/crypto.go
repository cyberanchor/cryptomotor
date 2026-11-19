// Package crypto implements all cryptographic operations for cryptomotor:
// Argon2id key derivation, AEAD encryption/decryption (AES-256-GCM and
// XChaCha20-Poly1305), HMAC-SHA512 integrity checks, and SHA-512 file
// hashing with streaming support.
//
// Security invariants enforced by this package:
//   - Every AEAD seal/open uses a UNIQUE nonce.  Three independent random
//     nonces are generated per file (payload, filename, hash) — fixing the
//     critical nonce-reuse bug from the Python v2.x implementation.
//   - HMAC is computed over CIPHERTEXT (Encrypt-then-MAC), not plaintext.
//   - Key material is zeroed after use where practical.
//
// Logging:
//
//	--debug logs only values that are stored in the encrypted file anyway
//	(salts, nonces, HMAC values) plus sizes and timings. Secrets (password,
//	derived key, plaintext hash) and per-chunk details are logged only at
//	the trace level (--trace).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"cryptomotor/internal/config"
	"cryptomotor/internal/logger"
	"cryptomotor/internal/progress"
)

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

var (
	ErrInvalidCipher    = errors.New("crypto: unknown cipher ID")
	ErrInvalidKey       = errors.New("crypto: wrong key length")
	ErrHMACMismatch     = errors.New("crypto: HMAC verification failed — wrong password or corrupted file")
	ErrAuthFailed       = errors.New("crypto: AEAD authentication failed — wrong password or corrupted data")
	ErrFileHashMismatch = errors.New("crypto: decrypted file hash does not match stored hash")
	ErrStreamFormat     = errors.New("crypto: malformed encrypted stream")
)

// ---------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------

// DeriveKey runs Argon2id with the given salt and returns a 32-byte key.
// lowMemory selects the reduced memory cost for constrained environments.
func DeriveKey(password []byte, salt []byte, lowMemory bool) []byte {
	mem := uint32(config.Argon2Memory)
	if lowMemory {
		mem = uint32(config.Argon2MemoryLow)
	}
	slog.Debug("Argon2id key derivation",
		"salt", hex.EncodeToString(salt),
		"memory_kib", mem,
		"iterations", config.Argon2Time,
		"parallelism", config.Argon2Threads,
	)
	logger.Trace("Argon2id input",
		"password", string(password),
		"password_hex", hex.EncodeToString(password),
		"password_bytes", len(password),
	)
	start := time.Now()
	key := argon2.IDKey(
		password,
		salt,
		config.Argon2Time,
		mem,
		config.Argon2Threads,
		config.Argon2KeyLen,
	)
	slog.Debug("Argon2id finished", "memory_kib", mem, "elapsed", time.Since(start).Round(time.Millisecond))
	logger.Trace("Derived key", "key", hex.EncodeToString(key))
	return key
}

// ---------------------------------------------------------------------
// AEAD construction
// ---------------------------------------------------------------------

// NewAEAD returns an AEAD cipher for the given key and cipher ID.
func NewAEAD(key []byte, cipherID config.CipherID) (cipher.AEAD, error) {
	if len(key) != config.Argon2KeyLen {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrInvalidKey, len(key), config.Argon2KeyLen)
	}
	switch cipherID {
	case config.CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes.NewCipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("cipher.NewGCM: %w", err)
		}
		return gcm, nil

	case config.CipherChaCha20Poly1305:
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("chacha20poly1305.NewX: %w", err)
		}
		return aead, nil

	default:
		return nil, ErrInvalidCipher
	}
}

// ---------------------------------------------------------------------
// Random nonce generation
// ---------------------------------------------------------------------

// GenerateNonce produces a cryptographically random nonce of exactly the
// size required by the given AEAD cipher.
func GenerateNonce(aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	slog.Debug("Generated nonce", "nonce", hex.EncodeToString(nonce), "size", len(nonce))
	return nonce, nil
}

// GenerateSalt produces a cryptographically random salt of SaltLen bytes.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, config.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	slog.Debug("Generated salt", "salt", hex.EncodeToString(salt))
	return salt, nil
}

// ---------------------------------------------------------------------
// Nonce encoding helpers
//
// The system block reserves 24 bytes for each nonce field.
// AES-GCM uses 12 bytes → right-aligned (left-padded with zeros).
// XChaCha uses 24 bytes → fills the entire field.
// ---------------------------------------------------------------------

// EncodeNonce writes an AEAD nonce into a 24-byte field, right-aligned.
func EncodeNonce(nonce []byte) [config.NonceFieldLen]byte {
	var field [config.NonceFieldLen]byte
	copy(field[config.NonceFieldLen-len(nonce):], nonce)
	return field
}

// DecodeNonce extracts the AEAD nonce from a 24-byte field based on cipher.
func DecodeNonce(field []byte, cipherID config.CipherID) []byte {
	size := cipherID.NonceSize()
	return field[config.NonceFieldLen-size:]
}

// ---------------------------------------------------------------------
// HMAC-SHA512  (Encrypt-then-MAC)
// ---------------------------------------------------------------------

// ComputeHMAC calculates HMAC-SHA512 over the provided data slices.
// The key is the Argon2id-derived key; salt is prepended to the message.
// NOTE: Use ComputeHMACStream for large data that should not be loaded into RAM.
func ComputeHMAC(key, salt []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(salt)
	totalLen := len(salt)
	for _, p := range parts {
		mac.Write(p)
		totalLen += len(p)
	}
	result := mac.Sum(nil)
	slog.Debug("Computed HMAC-SHA512",
		"hmac", hex.EncodeToString(result),
		"input_bytes", totalLen,
		"salt", hex.EncodeToString(salt),
	)
	return result
}

// VerifyHMAC performs a constant-time comparison of the expected and
// computed HMAC values.
// NOTE: Use VerifyHMACStream for large data that should not be loaded into RAM.
func VerifyHMAC(key, salt, expected []byte, parts ...[]byte) error {
	computed := ComputeHMAC(key, salt, parts...)
	if !hmac.Equal(computed, expected) {
		slog.Debug("HMAC verification FAILED",
			"expected", hex.EncodeToString(expected),
			"computed", hex.EncodeToString(computed),
		)
		return ErrHMACMismatch
	}
	slog.Debug("HMAC verification OK", "hmac", hex.EncodeToString(expected))
	return nil
}

// ComputeHMACStream calculates HMAC-SHA512 by streaming ciphertext from
// an io.Reader instead of loading it entirely into memory.
// Hash order: salt → ciphertext (streamed) → encFilename → encHash.
// This allows computing HMAC over multi-gigabyte files with constant
// memory usage (~1 MiB buffer).
func ComputeHMACStream(key, salt []byte, ciphertextReader io.Reader, encFilename, encHash []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, key)

	// 1. Salt prefix.
	mac.Write(salt)

	// 2. Stream ciphertext through HMAC in chunks — never buffer the whole file.
	buf := make([]byte, config.BufferSize)
	n, err := io.CopyBuffer(mac, ciphertextReader, buf)
	if err != nil {
		return nil, fmt.Errorf("stream ciphertext to HMAC: %w", err)
	}

	// 3. Append metadata.
	mac.Write(encFilename)
	mac.Write(encHash)

	result := mac.Sum(nil)
	slog.Debug("Computed HMAC-SHA512 (stream)",
		"hmac", hex.EncodeToString(result),
		"ciphertext_bytes", n,
		"salt", hex.EncodeToString(salt),
	)
	return result, nil
}

// VerifyHMACStream performs streaming HMAC computation and constant-time
// comparison.  The ciphertextReader is consumed exactly once.
func VerifyHMACStream(key, salt, expected []byte, ciphertextReader io.Reader, encFilename, encHash []byte) error {
	computed, err := ComputeHMACStream(key, salt, ciphertextReader, encFilename, encHash)
	if err != nil {
		return err
	}
	if !hmac.Equal(computed, expected) {
		slog.Debug("HMAC stream verification FAILED",
			"expected", hex.EncodeToString(expected),
			"computed", hex.EncodeToString(computed),
		)
		return ErrHMACMismatch
	}
	slog.Debug("HMAC stream verification OK", "hmac", hex.EncodeToString(expected))
	return nil
}

// ---------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------

// HashBytes computes SHA-512 over an in-memory byte slice.
func HashBytes(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// ---------------------------------------------------------------------
// Seal / Open helpers for small metadata blobs
// ---------------------------------------------------------------------

// Seal encrypts plaintext with the AEAD using a fresh random nonce.
// Returns (ciphertext, nonce, error).
func Seal(aead cipher.AEAD, plaintext []byte) (ciphertext, nonce []byte, err error) {
	nonce, err = GenerateNonce(aead)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	slog.Debug("AEAD Seal",
		"nonce", hex.EncodeToString(nonce),
		"plaintext_len", len(plaintext),
		"ciphertext_len", len(ciphertext),
	)
	return ciphertext, nonce, nil
}

// Open decrypts ciphertext with the AEAD and the given nonce.
func Open(aead cipher.AEAD, nonce, ciphertext []byte) ([]byte, error) {
	slog.Debug("AEAD Open",
		"nonce", hex.EncodeToString(nonce),
		"ciphertext_len", len(ciphertext),
	)
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		slog.Debug("AEAD Open FAILED", "nonce", hex.EncodeToString(nonce), "error", err)
		return nil, ErrAuthFailed
	}
	slog.Debug("AEAD Open OK", "plaintext_len", len(plaintext))
	return plaintext, nil
}

// ---------------------------------------------------------------------
// Streaming encryption / decryption for large payloads
//
// Each chunk is sealed with nonce = base_nonce XOR chunk_counter.
//
// Wire format per chunk:
//   [4 bytes big-endian ciphertext length][ciphertext + tag]
//
// A zero-length record ends the stream; nothing may follow it. The chunk
// size is chosen by the encoder (ChunkSize, or ChunkSizeLow with
// --low-memory) and is not stored: a decoder accepts any chunk up to
// ChunkSize plus the tag.
// ---------------------------------------------------------------------

// EncryptStream reads plaintext from r and writes chunk-encrypted data to w,
// sealing each chunk of at most chunkSize bytes in place in one reused buffer.
// It returns the number of plaintext bytes processed.
func EncryptStream(aead cipher.AEAD, baseNonce []byte, chunkSize int, r io.Reader, w io.Writer, showProgress bool, totalSize int64) (int64, error) {
	if chunkSize <= 0 || chunkSize > config.ChunkSize {
		return 0, fmt.Errorf("crypto: chunk size %d outside 1..%d", chunkSize, config.ChunkSize)
	}
	slog.Debug("EncryptStream started",
		"base_nonce", hex.EncodeToString(baseNonce),
		"chunk_size", chunkSize,
		"total_size", totalSize,
	)

	var bar *progress.Bar
	if showProgress && totalSize > 0 {
		bar = progress.New("Encrypting", totalSize)
	}

	buf := make([]byte, chunkSize+aead.Overhead())
	var counter uint64
	var written int64

	for {
		n, readErr := io.ReadFull(r, buf[:chunkSize])
		if n > 0 {
			nonce := deriveChunkNonce(baseNonce, counter)
			ct := aead.Seal(buf[:0], nonce, buf[:n], nil) // in place
			if logger.TraceEnabled() {
				logger.Trace("Encrypted chunk",
					"chunk", counter,
					"plaintext_len", n,
					"ciphertext_len", len(ct),
					"chunk_nonce", hex.EncodeToString(nonce),
					"tag", hex.EncodeToString(ct[len(ct)-aead.Overhead():]),
				)
			}
			counter++

			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
			if _, err := w.Write(lenBuf[:]); err != nil {
				return written, fmt.Errorf("write chunk length: %w", err)
			}
			if _, err := w.Write(ct); err != nil {
				return written, fmt.Errorf("write chunk data: %w", err)
			}
			written += int64(n)
			if bar != nil {
				bar.Add(int64(n))
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return written, fmt.Errorf("read plaintext: %w", readErr)
		}
	}

	// Write EOF sentinel (zero-length chunk).
	var eof [4]byte
	if _, err := w.Write(eof[:]); err != nil {
		return written, fmt.Errorf("write EOF sentinel: %w", err)
	}

	if bar != nil {
		bar.Finish()
	}
	slog.Debug("EncryptStream finished", "chunks", counter, "plaintext_bytes", written)
	return written, nil
}

// DecryptStream reads chunk-encrypted data from r and writes plaintext to w.
// It returns the number of plaintext bytes written. The stream must end with
// the zero-length record and nothing after it; a chunk longer than
// ChunkSize plus the tag is rejected before any memory is allocated for it.
// Truncation exactly at a chunk boundary (with a new end record) cannot be
// seen here: at file level HMAC and the SHA-512 of the plaintext catch it.
func DecryptStream(aead cipher.AEAD, baseNonce []byte, r io.Reader, w io.Writer, showProgress bool, totalSize int64) (int64, error) {
	slog.Debug("DecryptStream started",
		"base_nonce", hex.EncodeToString(baseNonce),
		"total_size", totalSize,
	)

	var bar *progress.Bar
	if showProgress && totalSize > 0 {
		bar = progress.New("Decrypting", totalSize)
	}

	maxLen := uint32(config.ChunkSize + aead.Overhead())
	var buf []byte
	var counter uint64
	var written, consumed, reported int64
	var lenBuf [4]byte

	for {
		// Read chunk length.
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return written, fmt.Errorf("%w: missing end-of-stream record after %d chunks", ErrStreamFormat, counter)
			}
			return written, fmt.Errorf("read chunk length: %w", err)
		}
		consumed += 4
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		if chunkLen == 0 {
			break // EOF sentinel
		}
		if chunkLen <= uint32(aead.Overhead()) || chunkLen > maxLen {
			return written, fmt.Errorf("%w: chunk %d has length %d (allowed %d..%d)",
				ErrStreamFormat, counter, chunkLen, aead.Overhead()+1, maxLen)
		}

		if uint32(cap(buf)) < chunkLen {
			buf = make([]byte, chunkLen)
		}
		ct := buf[:chunkLen]
		if _, err := io.ReadFull(r, ct); err != nil {
			return written, fmt.Errorf("read chunk data: %w", err)
		}
		consumed += int64(chunkLen)

		nonce := deriveChunkNonce(baseNonce, counter)
		pt, err := aead.Open(ct[:0], nonce, ct, nil) // in place
		if logger.TraceEnabled() {
			logger.Trace("Decrypted chunk",
				"chunk", counter,
				"ciphertext_len", chunkLen,
				"chunk_nonce", hex.EncodeToString(nonce),
				"ok", err == nil,
			)
		}
		if err != nil {
			slog.Debug("Chunk decryption FAILED", "chunk", counter, "error", err)
			return written, ErrAuthFailed
		}
		counter++
		if _, err := w.Write(pt); err != nil {
			return written, fmt.Errorf("write plaintext: %w", err)
		}
		written += int64(len(pt))
		if bar != nil { // the total is the ciphertext size
			bar.Add(consumed - reported)
			reported = consumed
		}
	}

	// Nothing may follow the end record.
	var extra [1]byte
	if n, _ := r.Read(extra[:]); n > 0 {
		return written, fmt.Errorf("%w: data after the end-of-stream record", ErrStreamFormat)
	}

	if bar != nil {
		bar.Finish()
	}
	slog.Debug("DecryptStream finished", "chunks", counter, "plaintext_bytes", written)
	return written, nil
}

// deriveChunkNonce XORs a 64-bit big-endian counter into the last 8 bytes
// of the base nonce, producing a unique nonce per chunk.
func deriveChunkNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)

	// XOR counter into the last 8 bytes.
	offset := len(nonce) - 8
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	for i := 0; i < 8; i++ {
		nonce[offset+i] ^= ctr[i]
	}
	return nonce
}

// ZeroBytes overwrites a byte slice with zeros.
// Use to clear key material when it is no longer needed.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
