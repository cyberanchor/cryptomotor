package crypto_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20"

	"cryptomotor/internal/config"
	"cryptomotor/internal/crypto"
)

// TestDeriveKeyDeterministic verifies that the same password+salt always
// produces the same key, and different salts produce different keys.
func TestDeriveKeyDeterministic(t *testing.T) {
	password := []byte("test-password-42")
	salt := make([]byte, config.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	k1 := crypto.DeriveKey(password, salt, true) // low-memory for fast tests
	k2 := crypto.DeriveKey(password, salt, true)
	if !bytes.Equal(k1, k2) {
		t.Fatal("same password+salt must produce identical keys")
	}

	salt2 := make([]byte, config.SaltLen)
	copy(salt2, salt)
	salt2[0] ^= 0xff
	k3 := crypto.DeriveKey(password, salt2, true)
	if bytes.Equal(k1, k3) {
		t.Fatal("different salts must produce different keys")
	}
}

// TestSealOpenRoundTrip verifies encryption followed by decryption returns
// the original plaintext for both supported ciphers.
func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	for _, cid := range []config.CipherID{config.CipherAES256GCM, config.CipherChaCha20Poly1305} {
		t.Run(cid.String(), func(t *testing.T) {
			aead, err := crypto.NewAEAD(key, cid)
			if err != nil {
				t.Fatal(err)
			}

			plaintext := []byte("hello, cryptomotor v3")
			ct, nonce, err := crypto.Seal(aead, plaintext)
			if err != nil {
				t.Fatal(err)
			}

			pt, err := crypto.Open(aead, nonce, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("round-trip mismatch: got %q, want %q", pt, plaintext)
			}
		})
	}
}

// TestSealUniqueNonces verifies that each Seal call produces a different nonce.
func TestSealUniqueNonces(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	aead, _ := crypto.NewAEAD(key, config.CipherChaCha20Poly1305)
	_, n1, _ := crypto.Seal(aead, []byte("a"))
	_, n2, _ := crypto.Seal(aead, []byte("b"))
	_, n3, _ := crypto.Seal(aead, []byte("c"))

	if bytes.Equal(n1, n2) || bytes.Equal(n2, n3) || bytes.Equal(n1, n3) {
		t.Fatal("each Seal must use a unique nonce")
	}
}

// TestHMACVerify checks that correct HMAC passes and tampered data fails.
func TestHMACVerify(t *testing.T) {
	key := []byte("hmac-key-32-bytes-long-enough-xx")
	salt := []byte("salt")
	data := []byte("payload")

	mac := crypto.ComputeHMAC(key, salt, data)
	if err := crypto.VerifyHMAC(key, salt, mac, data); err != nil {
		t.Fatal("valid HMAC should verify")
	}

	// Tamper with data.
	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0xff
	if err := crypto.VerifyHMAC(key, salt, mac, tampered); err == nil {
		t.Fatal("tampered data should fail HMAC check")
	}
}

// TestStreamRoundTrip verifies streaming encryption+decryption for both ciphers
// with the real 64 MiB chunk size: 3 full chunks plus a partial one. The data
// flows through a pipe and only hashes are compared, so the test needs about
// two chunk buffers of memory instead of three copies of the whole stream.
func TestStreamRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("192 MiB stream: skipped with -short")
	}
	key := make([]byte, 32)
	rand.Read(key)
	const size = config.ChunkSize*3 + 12345

	for _, cid := range []config.CipherID{config.CipherAES256GCM, config.CipherChaCha20Poly1305} {
		t.Run(cid.String(), func(t *testing.T) {
			aead, _ := crypto.NewAEAD(key, cid)
			baseNonce, _ := crypto.GenerateNonce(aead)
			src := sha512.New()
			plain := io.TeeReader(io.LimitReader(newPRNG(cid), size), src)

			pr, pw := io.Pipe()
			go func() {
				_, err := crypto.EncryptStream(aead, baseNonce, config.ChunkSize, plain, pw, false, size)
				pw.CloseWithError(err)
			}()
			dst := sha512.New()
			n, err := crypto.DecryptStream(aead, baseNonce, pr, dst, false, 0)
			if err != nil {
				t.Fatal(err)
			}
			if n != size || !bytes.Equal(dst.Sum(nil), src.Sum(nil)) {
				t.Fatalf("stream round-trip failed: got %d bytes, want %d", n, size)
			}
		})
	}
}

// newPRNG returns a fast deterministic byte stream (ChaCha20 keystream).
func newPRNG(seed config.CipherID) io.Reader {
	key := make([]byte, 32)
	key[0] = byte(seed)
	c, _ := chacha20.NewUnauthenticatedCipher(key, make([]byte, 12))
	return cipher.StreamReader{S: c, R: zeroReader{}}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestHashBytes verifies the SHA-512 helper against the standard library.
func TestHashBytes(t *testing.T) {
	data := make([]byte, 1024*1024)
	rand.Read(data)
	want := sha512.Sum512(data)
	if !bytes.Equal(crypto.HashBytes(data), want[:]) {
		t.Fatal("HashBytes does not match sha512.Sum512")
	}
}

// TestNonceEncodeDecode verifies nonce field encoding round-trips correctly.
func TestNonceEncodeDecode(t *testing.T) {
	// XChaCha: 24 bytes fills entire field.
	nonce24 := make([]byte, 24)
	rand.Read(nonce24)
	field := crypto.EncodeNonce(nonce24)
	decoded := crypto.DecodeNonce(field[:], config.CipherChaCha20Poly1305)
	if !bytes.Equal(decoded, nonce24) {
		t.Fatal("XChaCha nonce round-trip failed")
	}

	// AES-GCM: 12 bytes right-aligned.
	nonce12 := make([]byte, 12)
	rand.Read(nonce12)
	field = crypto.EncodeNonce(nonce12)
	decoded = crypto.DecodeNonce(field[:], config.CipherAES256GCM)
	if !bytes.Equal(decoded, nonce12) {
		t.Fatal("AES-GCM nonce round-trip failed")
	}

	// Verify left padding is zeros.
	for i := 0; i < 12; i++ {
		if field[i] != 0 {
			t.Fatalf("expected zero padding at position %d, got 0x%02x", i, field[i])
		}
	}
}

// TestZeroBytes verifies key material is properly wiped.
func TestZeroBytes(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	crypto.ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: 0x%02x", i, b)
		}
	}
}

// TestStreamTamperedChunk verifies that tampering with a ciphertext chunk
// causes an authentication error on decryption.
func TestStreamTamperedChunk(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	aead, _ := crypto.NewAEAD(key, config.CipherChaCha20Poly1305)
	baseNonce, _ := crypto.GenerateNonce(aead)

	plaintext := []byte("tamper test data that is long enough to be meaningful")
	var ctBuf bytes.Buffer
	crypto.EncryptStream(aead, baseNonce, config.ChunkSize, bytes.NewReader(plaintext), &ctBuf, false, int64(len(plaintext)))

	// Flip a byte in the ciphertext (after the 4-byte length prefix).
	ct := ctBuf.Bytes()
	if len(ct) > 10 {
		ct[10] ^= 0xff
	}

	var ptBuf bytes.Buffer
	_, err := crypto.DecryptStream(aead, baseNonce, bytes.NewReader(ct), &ptBuf, false, int64(len(ct)))
	if err == nil {
		t.Fatal("expected auth error on tampered ciphertext")
	}
}

// BenchmarkDeriveKeyLowMemory measures Argon2id performance in low-memory mode.
func BenchmarkDeriveKeyLowMemory(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, config.SaltLen)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.DeriveKey(password, salt, true)
	}
}

// BenchmarkStreamEncrypt measures streaming encryption throughput.
func BenchmarkStreamEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, _ := crypto.NewAEAD(key, config.CipherChaCha20Poly1305)
	nonce, _ := crypto.GenerateNonce(aead)

	data := make([]byte, 64*1024*1024) // 64 MiB
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.EncryptStream(aead, nonce, config.ChunkSize, bytes.NewReader(data), io.Discard, false, int64(len(data)))
	}
}

// TestHMACStreamMatchesInMemory verifies that ComputeHMACStream produces
// the same result as ComputeHMAC for identical input.
func TestHMACStreamMatchesInMemory(t *testing.T) {
	key := []byte("hmac-key-32-bytes-long-enough-xx")
	salt := []byte("test-salt")
	ciphertext := make([]byte, 1024*1024) // 1 MiB
	rand.Read(ciphertext)
	encFilename := make([]byte, 512)
	rand.Read(encFilename)
	encHash := make([]byte, 80)
	rand.Read(encHash)

	// In-memory HMAC.
	inMemory := crypto.ComputeHMAC(key, salt, ciphertext, encFilename, encHash)

	// Streaming HMAC over the same data.
	streamed, err := crypto.ComputeHMACStream(key, salt, bytes.NewReader(ciphertext), encFilename, encHash)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(inMemory, streamed) {
		t.Fatal("streaming HMAC must match in-memory HMAC for identical input")
	}
}

// TestVerifyHMACStreamRejectsTampered checks that a flipped byte causes failure.
func TestVerifyHMACStreamRejectsTampered(t *testing.T) {
	key := []byte("hmac-key-32-bytes-long-enough-xx")
	salt := []byte("salt")
	data := []byte("original-payload")
	encFn := []byte("enc-filename")
	encH := []byte("enc-hash")

	good, _ := crypto.ComputeHMACStream(key, salt, bytes.NewReader(data), encFn, encH)

	// Tamper with one byte.
	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0xff

	err := crypto.VerifyHMACStream(key, salt, good, bytes.NewReader(tampered), encFn, encH)
	if err == nil {
		t.Fatal("tampered ciphertext should fail streaming HMAC verification")
	}
}
