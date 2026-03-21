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
// Debug logging:
//   When --debug is enabled, all cryptographic material (keys, salts, nonces,
//   HMAC values) is written to the log for troubleshooting.  Do NOT use
//   --debug in production — it exposes secrets in the log file.
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
	"hash"
	"io"
	"log/slog"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"cryptomotor/internal/config"
	"cryptomotor/internal/progress"
)

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

var (
	ErrInvalidCipher    = errors.New("crypto: unknown cipher ID")
	ErrNonceMismatch    = errors.New("crypto: nonce length mismatch")
	ErrHMACMismatch     = errors.New("crypto: HMAC verification failed — wrong password or corrupted file")
	ErrAuthFailed       = errors.New("crypto: AEAD authentication failed — wrong password or corrupted data")
	ErrFileHashMismatch = errors.New("crypto: decrypted file hash does not match stored hash")
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
	key := argon2.IDKey(
		password,
		salt,
		config.Argon2Time,
		mem,
		config.Argon2Threads,
		config.Argon2KeyLen,
	)
	slog.Debug("Derived key", "key", hex.EncodeToString(key))
	return key
}

// ---------------------------------------------------------------------
// AEAD construction
// ---------------------------------------------------------------------

// NewAEAD returns an AEAD cipher for the given key and cipher ID.
func NewAEAD(key []byte, cipherID config.CipherID) (cipher.AEAD, error) {
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
// File hashing (SHA-512, streaming)
// ---------------------------------------------------------------------

// HashFile computes the SHA-512 digest of the file at path, reading in
// chunks of bufSize bytes.  If showProgress is true a terminal progress
// bar is rendered.
func HashFile(path string, bufSize int, showProgress bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open for hashing: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat for hashing: %w", err)
	}

	slog.Debug("Computing SHA-512 hash", "file", path, "size", info.Size(), "buffer", bufSize)

	h := sha512.New()
	var result []byte
	if showProgress && info.Size() > int64(bufSize)*10 {
		result, err = hashWithProgress(f, h, bufSize, info.Size())
	} else {
		result, err = hashPlain(f, h, bufSize)
	}
	if err != nil {
		return nil, err
	}

	slog.Debug("Computed SHA-512 hash", "file", path, "hash", hex.EncodeToString(result))
	return result, nil
}

func hashPlain(r io.Reader, h hash.Hash, bufSize int) ([]byte, error) {
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read for hash: %w", err)
		}
	}
	return h.Sum(nil), nil
}

func hashWithProgress(r io.Reader, h hash.Hash, bufSize int, total int64) ([]byte, error) {
	bar := progress.New("Hashing", total)
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			bar.Add(int64(n))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read for hash: %w", err)
		}
	}
	bar.Finish()
	return h.Sum(nil), nil
}

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
// The last chunk is identified by its shorter length.
//
// Wire format per chunk:
//   [4 bytes big-endian ciphertext length][ciphertext + tag]
//
// A zero-length record signals EOF.
// ---------------------------------------------------------------------

// EncryptStream reads plaintext from r and writes chunk-encrypted data to w.
// It returns the number of plaintext bytes processed.
func EncryptStream(aead cipher.AEAD, baseNonce []byte, r io.Reader, w io.Writer, showProgress bool, totalSize int64) (int64, error) {
	slog.Debug("EncryptStream started",
		"base_nonce", hex.EncodeToString(baseNonce),
		"chunk_size", config.ChunkSize,
		"total_size", totalSize,
	)

	var bar *progress.Bar
	if showProgress && totalSize > 0 {
		bar = progress.New("Encrypting", totalSize)
	}

	buf := make([]byte, config.ChunkSize)
	var counter uint64
	var written int64

	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			nonce := deriveChunkNonce(baseNonce, counter)
			slog.Debug("Encrypting chunk",
				"chunk", counter,
				"plaintext_len", n,
				"chunk_nonce", hex.EncodeToString(nonce),
			)
			counter++

			ct := aead.Seal(nil, nonce, buf[:n], nil)

			// Write chunk length prefix.
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
// It returns the number of plaintext bytes written.
func DecryptStream(aead cipher.AEAD, baseNonce []byte, r io.Reader, w io.Writer, showProgress bool, totalSize int64) (int64, error) {
	slog.Debug("DecryptStream started",
		"base_nonce", hex.EncodeToString(baseNonce),
		"total_size", totalSize,
	)

	var bar *progress.Bar
	if showProgress && totalSize > 0 {
		bar = progress.New("Decrypting", totalSize)
	}

	var counter uint64
	var written int64
	var lenBuf [4]byte

	for {
		// Read chunk length.
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return written, fmt.Errorf("read chunk length: %w", err)
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		if chunkLen == 0 {
			break // EOF sentinel
		}

		ct := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ct); err != nil {
			return written, fmt.Errorf("read chunk data: %w", err)
		}

		nonce := deriveChunkNonce(baseNonce, counter)
		slog.Debug("Decrypting chunk",
			"chunk", counter,
			"ciphertext_len", chunkLen,
			"chunk_nonce", hex.EncodeToString(nonce),
		)
		counter++

		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			slog.Debug("Chunk decryption FAILED", "chunk", counter-1, "error", err)
			return written, ErrAuthFailed
		}
		if _, err := w.Write(pt); err != nil {
			return written, fmt.Errorf("write plaintext: %w", err)
		}
		written += int64(len(pt))
		if bar != nil {
			bar.Add(int64(len(pt)))
		}
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
