// Package config defines all cryptographic and format constants for cryptomotor.
//
// This package is the single source of truth for the file format layout,
// Argon2id tuning parameters, buffer sizes, and cipher selection.
// Changing a constant here propagates to every subsystem automatically.
package config

import "time"

// ---------------------------------------------------------------------
// Program metadata
// ---------------------------------------------------------------------

const (
	// ProgramName is the human-readable name shown in CLI banners and logs.
	ProgramName = "cryptomotor"

	// ProgramVersion follows semver; bump on every format or behaviour change.
	// The Makefile and the release workflow read the version from this line.
	ProgramVersion = "3.0.0"
)

// ---------------------------------------------------------------------
// Cipher selection
// ---------------------------------------------------------------------

// CipherID identifies which AEAD cipher was used to encrypt a file.
// It is stored in the system block so the decryptor can pick the right
// primitive without guessing.
type CipherID byte

const (
	// CipherAES256GCM selects AES-256-GCM (128-bit tag, 12-byte nonce).
	CipherAES256GCM CipherID = 0x01

	// CipherChaCha20Poly1305 selects XChaCha20-Poly1305 (24-byte nonce).
	// Preferred on platforms without AES-NI hardware acceleration.
	CipherChaCha20Poly1305 CipherID = 0x02
)

// String returns a human-readable cipher name for logs and UI.
func (c CipherID) String() string {
	switch c {
	case CipherAES256GCM:
		return "AES-256-GCM"
	case CipherChaCha20Poly1305:
		return "XChaCha20-Poly1305"
	default:
		return "unknown"
	}
}

// NonceSize returns the expected nonce length in bytes for the cipher.
func (c CipherID) NonceSize() int {
	switch c {
	case CipherAES256GCM:
		return 12
	case CipherChaCha20Poly1305:
		return 24
	default:
		return 0
	}
}

// ---------------------------------------------------------------------
// Key derivation mode
// ---------------------------------------------------------------------

// KDFMode records the Argon2id memory cost in the system block, so that a
// file can be decrypted without remembering --low-memory. It occupies the
// byte that was reserved (always 0x00) up to version 3.1.0; older versions
// ignore it, so they still read files written by newer ones.
type KDFMode byte

const (
	// KDFUnrecorded marks files written by cryptomotor 3.1.0 and earlier.
	// Their memory cost is unknown: decryption tries 64 MiB, then 4 GiB.
	KDFUnrecorded KDFMode = 0x00

	// KDFLowMemory is Argon2id with Argon2MemoryLow (64 MiB).
	KDFLowMemory KDFMode = 0x01

	// KDFStandard is Argon2id with Argon2Memory (4 GiB).
	KDFStandard KDFMode = 0x02
)

// Valid reports whether m is a mode this version understands.
func (m KDFMode) Valid() bool {
	return m == KDFUnrecorded || m == KDFLowMemory || m == KDFStandard
}

// MemoryKiB returns the Argon2id memory cost of a recorded mode.
func (m KDFMode) MemoryKiB() uint32 {
	if m == KDFLowMemory {
		return Argon2MemoryLow
	}
	return Argon2Memory
}

// String returns a human-readable description for logs and --analyze.
func (m KDFMode) String() string {
	switch m {
	case KDFUnrecorded:
		return "not recorded (written by 3.1.0 or earlier)"
	case KDFLowMemory:
		return "Argon2id 64 MiB (--low-memory)"
	case KDFStandard:
		return "Argon2id 4 GiB"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------
// System block layout  (v3 format)
//
//  Offset  Length  Field
//  ------  ------  ------------------------------------------
//      0       8   Signature  ("CMv3\x00\x00\x00\x00")
//      8       1   CipherID   (0x01 = AES-GCM, 0x02 = XChaCha)
//      9       1   KDFMode    (0x00 = not recorded, 0x01 = 64 MiB, 0x02 = 4 GiB)
//     10      64   Salt       (random, Argon2id input)
//     74      24   NoncePayload   (XChaCha nonce for payload)
//     98      24   NonceFilename  (XChaCha nonce for filename)
//    122      24   NonceHash      (XChaCha nonce for file hash)
//    146      64   HMAC-SHA512    (over salt + stream + enc_filename + enc_hash)
//    210       4   PaddedNameLen  (big-endian, always 496)
//    214     512   EncFilename    (496-byte zero-padded name + 16-byte tag)
//    726      80   EncHash        (64-byte SHA-512 + 16-byte tag)
//    806       4   OrigNameLen    (big-endian, original UTF-8 byte count)
//    ---------------------------------------------------------------
//    Total: 810 bytes
//
// For AES-256-GCM (12-byte nonces) the nonce fields are left-padded
// with zeros; only the rightmost 12 bytes are used.
//
// HMAC does not cover the header itself. Every header field is therefore
// either checked against a fixed value (signature, PaddedNameLen, AES nonce
// padding), bound to the key (KDFMode, salt) or to an AEAD tag (cipher,
// nonces), or cross-checked with the decrypted name (OrigNameLen).
// ---------------------------------------------------------------------

const (
	// Signature is the magic bytes that identify a v3 cryptomotor file.
	Signature = "CMv3\x00\x00\x00\x00"

	// SignatureLen is the byte length of the file signature.
	SignatureLen = 8

	// CipherIDLen is the byte length of the cipher identifier field.
	CipherIDLen = 1

	// KDFModeLen is the byte length of the KDF mode field.
	KDFModeLen = 1

	// SaltLen is the byte length of the Argon2id salt.
	SaltLen = 64

	// NonceFieldLen is the fixed width of each nonce slot in the header.
	// XChaCha20-Poly1305 uses all 24 bytes; AES-GCM uses the last 12.
	NonceFieldLen = 24

	// HMACLen is the byte length of the HMAC-SHA512 output.
	HMACLen = 64

	// FilenameLenField is the byte width of the padded-filename-length value.
	FilenameLenField = 4

	// PaddedFilenameLen is the fixed plaintext size of the padded filename,
	// and the only value the field at offset 210 may hold.
	PaddedFilenameLen = 496

	// EncFilenameLen is PaddedFilenameLen + 16-byte GCM/Poly1305 auth tag.
	EncFilenameLen = 512

	// EncHashLen is 64-byte SHA-512 digest + 16-byte auth tag.
	EncHashLen = 80

	// OrigNameLenField is the byte width of the original filename length.
	OrigNameLenField = 4

	// SystemBlockLen is the total header size preceding the encrypted payload.
	SystemBlockLen = SignatureLen + CipherIDLen + KDFModeLen +
		SaltLen + 3*NonceFieldLen + HMACLen +
		FilenameLenField + EncFilenameLen + EncHashLen + OrigNameLenField // = 810
)

// SystemBlockOffsets holds pre-computed byte offsets for every field.
// Use these instead of manual arithmetic to avoid off-by-one errors.
var SystemBlockOffsets = struct {
	Signature     int
	CipherID      int
	KDFMode       int
	Salt          int
	NoncePayload  int
	NonceFilename int
	NonceHash     int
	HMAC          int
	FilenameLen   int
	EncFilename   int
	EncHash       int
	OrigNameLen   int
}{
	Signature:     0,
	CipherID:      SignatureLen,
	KDFMode:       SignatureLen + CipherIDLen,
	Salt:          SignatureLen + CipherIDLen + KDFModeLen,
	NoncePayload:  SignatureLen + CipherIDLen + KDFModeLen + SaltLen,
	NonceFilename: SignatureLen + CipherIDLen + KDFModeLen + SaltLen + NonceFieldLen,
	NonceHash:     SignatureLen + CipherIDLen + KDFModeLen + SaltLen + 2*NonceFieldLen,
	HMAC:          SignatureLen + CipherIDLen + KDFModeLen + SaltLen + 3*NonceFieldLen,
	FilenameLen:   SignatureLen + CipherIDLen + KDFModeLen + SaltLen + 3*NonceFieldLen + HMACLen,
	EncFilename:   SignatureLen + CipherIDLen + KDFModeLen + SaltLen + 3*NonceFieldLen + HMACLen + FilenameLenField,
	EncHash:       SignatureLen + CipherIDLen + KDFModeLen + SaltLen + 3*NonceFieldLen + HMACLen + FilenameLenField + EncFilenameLen,
	OrigNameLen:   SignatureLen + CipherIDLen + KDFModeLen + SaltLen + 3*NonceFieldLen + HMACLen + FilenameLenField + EncFilenameLen + EncHashLen,
}

// ---------------------------------------------------------------------
// Argon2id parameters
// ---------------------------------------------------------------------

const (
	// Argon2Time is the number of passes over memory (iterations).
	Argon2Time = 8

	// Argon2Memory is the default memory cost in KiB (4 GiB).
	Argon2Memory = 4 * 1024 * 1024

	// Argon2MemoryLow is the memory cost for constrained systems (64 MiB).
	Argon2MemoryLow = 64 * 1024

	// Argon2Threads is the degree of parallelism.
	Argon2Threads = 8

	// Argon2KeyLen is the derived key length in bytes (256-bit).
	Argon2KeyLen = 32

	// Argon2MemoryThreshold is the minimum available RAM (in bytes) below
	// which encryption automatically falls back to Argon2MemoryLow. The
	// chosen mode is recorded in the file, so decryption needs no flag.
	Argon2MemoryThreshold = 8 * 1024 * 1024 * 1024 // 8 GiB

	// Argon2MemoryHeadroom is the RAM (in bytes) required on top of
	// Argon2Memory before a 4 GiB derivation is started at all. Without it
	// the derivation swaps for a very long time or is killed for lack of memory.
	Argon2MemoryHeadroom = 512 * 1024 * 1024 // 512 MiB
)

// ---------------------------------------------------------------------
// I/O tuning
// ---------------------------------------------------------------------

const (
	// BufferSize is the default streaming read/write buffer (1 MiB).
	BufferSize = 1 << 20

	// ChunkSize is the AEAD plaintext chunk for streaming encryption.
	// Each chunk is encrypted independently with a unique nonce derived
	// from a base nonce + chunk counter.  64 MiB balances throughput
	// against memory pressure. It is also the largest chunk a decoder
	// accepts.
	ChunkSize = 64 * 1024 * 1024

	// ChunkSizeLow is the plaintext chunk used with --low-memory (512 KiB).
	// The chunk size is not stored in the file: every version decodes any
	// chunk up to ChunkSize.
	ChunkSizeLow = 512 * 1024

	// ProgressInterval is the minimum time between progress bar updates.
	ProgressInterval = 250 * time.Millisecond
)

// ---------------------------------------------------------------------
// Filename constraints
// ---------------------------------------------------------------------

const (
	// MaxFilenameBytes is the maximum original filename length in UTF-8 bytes:
	// the whole padded field. Linux allows at most 255 bytes, but a Windows
	// name of 255 UTF-16 units can need more.
	MaxFilenameBytes = PaddedFilenameLen

	// RandomFilenameLen is the character count of generated output filenames.
	RandomFilenameLen = 32

	// MaxPasswordLen is the recommended upper bound; longer passwords emit a warning.
	MaxPasswordLen = 4096
)

// OldSignature is the v2 magic bytes; used only for a friendly error message
// when the user accidentally feeds a v2 file to the v3 tool.
const OldSignature = "CRYPTv2\x00"
