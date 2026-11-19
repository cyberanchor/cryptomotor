package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"cryptomotor/internal/config"
)

var ciphers = []config.CipherID{config.CipherAES256GCM, config.CipherChaCha20Poly1305}

func newTestAEAD(t *testing.T, id config.CipherID) cipher.AEAD {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	a, err := NewAEAD(key, id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// silenceStderr hides progress bars written straight to os.Stderr.
func silenceStderr(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = devnull
	t.Cleanup(func() { os.Stderr = old; devnull.Close() })
}

// sealChunks builds a stream of small chunks the way EncryptStream frames them,
// so multi-chunk behaviour can be tested without 64 MiB buffers.
func sealChunks(a cipher.AEAD, base []byte, chunks [][]byte, sentinel bool) []byte {
	var out bytes.Buffer
	for i, c := range chunks {
		ct := a.Seal(nil, deriveChunkNonce(base, uint64(i)), c, nil)
		binary.Write(&out, binary.BigEndian, uint32(len(ct)))
		out.Write(ct)
	}
	if sentinel {
		out.Write([]byte{0, 0, 0, 0})
	}
	return out.Bytes()
}

func TestDeriveChunkNonce(t *testing.T) {
	for _, size := range []int{12, 24} {
		base := make([]byte, size)
		rand.Read(base)
		orig := bytes.Clone(base)
		if !bytes.Equal(deriveChunkNonce(base, 0), base) {
			t.Fatalf("size %d: counter 0 must return the base nonce", size)
		}
		seen := map[string]bool{}
		for c := uint64(0); c < 5000; c++ {
			n := deriveChunkNonce(base, c)
			if len(n) != size {
				t.Fatalf("length %d, want %d", len(n), size)
			}
			if !bytes.Equal(n[:size-8], base[:size-8]) {
				t.Fatalf("counter %d changed the nonce prefix", c)
			}
			if seen[string(n)] {
				t.Fatalf("size %d: nonce repeats at counter %d", size, c)
			}
			seen[string(n)] = true
		}
		last := deriveChunkNonce(base, ^uint64(0))
		for i := size - 8; i < size; i++ {
			if last[i] != ^base[i] {
				t.Fatalf("counter 2^64-1 must invert the last 8 bytes")
			}
		}
		if !bytes.Equal(base, orig) {
			t.Fatal("deriveChunkNonce modified its input")
		}
	}
}

func TestStreamRoundTripSmallSizes(t *testing.T) {
	for _, id := range ciphers {
		a := newTestAEAD(t, id)
		for _, chunk := range []int{7, 4096, config.ChunkSizeLow, config.ChunkSize} {
			for _, n := range []int{0, 1, 6, 7, 8, 15, 16, 17, 4096, 1<<20 + 3} {
				base, _ := GenerateNonce(a)
				pt := make([]byte, n)
				rand.Read(pt)
				var ct bytes.Buffer
				w, err := EncryptStream(a, base, chunk, bytes.NewReader(pt), &ct, false, int64(n))
				if err != nil || w != int64(n) {
					t.Fatalf("%s chunk=%d n=%d: encrypt wrote %d, err %v", id, chunk, n, w, err)
				}
				chunks := (n + chunk - 1) / chunk
				if want := n + chunks*(4+a.Overhead()) + 4; ct.Len() != want {
					t.Fatalf("%s chunk=%d n=%d: stream length %d, want %d", id, chunk, n, ct.Len(), want)
				}
				var back bytes.Buffer
				r, err := DecryptStream(a, base, &ct, &back, false, int64(ct.Len()))
				if err != nil || r != int64(n) || !bytes.Equal(back.Bytes(), pt) {
					t.Fatalf("%s chunk=%d n=%d: decrypt read %d, err %v, equal %v", id, chunk, n, r, err, bytes.Equal(back.Bytes(), pt))
				}
			}
		}
	}
}

func TestEncryptStreamRejectsBadChunkSize(t *testing.T) {
	a := newTestAEAD(t, config.CipherChaCha20Poly1305)
	base, _ := GenerateNonce(a)
	for _, size := range []int{0, -1, config.ChunkSize + 1} {
		if _, err := EncryptStream(a, base, size, bytes.NewReader([]byte("x")), io.Discard, false, 1); err == nil {
			t.Errorf("chunk size %d accepted", size)
		}
	}
}

func TestStreamOneByteReader(t *testing.T) {
	a := newTestAEAD(t, config.CipherChaCha20Poly1305)
	base, _ := GenerateNonce(a)
	pt := make([]byte, 3000)
	rand.Read(pt)
	var ct bytes.Buffer
	if _, err := EncryptStream(a, base, 1000, iotest.OneByteReader(bytes.NewReader(pt)), &ct, false, 3000); err != nil {
		t.Fatal(err)
	}
	var back bytes.Buffer
	if _, err := DecryptStream(a, base, iotest.OneByteReader(&ct), &back, false, 0); err != nil || !bytes.Equal(back.Bytes(), pt) {
		t.Fatalf("one-byte reads: err %v", err)
	}
}

func TestDecryptStreamMultiChunkIntegrity(t *testing.T) {
	a := newTestAEAD(t, config.CipherChaCha20Poly1305)
	base, _ := GenerateNonce(a)
	chunks := [][]byte{[]byte("chunk zero"), []byte("chunk one"), []byte("chunk two")}
	good := sealChunks(a, base, chunks, true)
	var out bytes.Buffer
	if _, err := DecryptStream(a, base, bytes.NewReader(good), &out, false, 0); err != nil || out.String() != "chunk zerochunk onechunk two" {
		t.Fatalf("multi-chunk decrypt: %q %v", out.String(), err)
	}
	cases := map[string][][]byte{
		"swapped chunks":   {chunks[1], chunks[0], chunks[2]},
		"dropped middle":   {chunks[0], chunks[2]},
		"duplicated chunk": {chunks[0], chunks[0], chunks[1], chunks[2]},
	}
	for name, order := range cases {
		// Re-seal each plaintext at its ORIGINAL index, then reorder the records.
		var recs [][]byte
		for _, c := range order {
			idx := 0
			for i := range chunks {
				if bytes.Equal(chunks[i], c) {
					idx = i
				}
			}
			ct := a.Seal(nil, deriveChunkNonce(base, uint64(idx)), c, nil)
			rec := make([]byte, 4+len(ct))
			binary.BigEndian.PutUint32(rec, uint32(len(ct)))
			copy(rec[4:], ct)
			recs = append(recs, rec)
		}
		stream := append(bytes.Join(recs, nil), 0, 0, 0, 0)
		if _, err := DecryptStream(a, base, bytes.NewReader(stream), io.Discard, false, 0); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("%s: err = %v, want ErrAuthFailed", name, err)
		}
	}
	// Wrong base nonce and a flipped tag byte.
	other, _ := GenerateNonce(a)
	if _, err := DecryptStream(a, other, bytes.NewReader(good), io.Discard, false, 0); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("wrong base nonce: %v", err)
	}
	bad := bytes.Clone(good)
	bad[4+10+a.Overhead()-1] ^= 1
	if _, err := DecryptStream(a, base, bytes.NewReader(bad), io.Discard, false, 0); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("flipped tag: %v", err)
	}
	// Declared length longer than the data.
	short := []byte{0, 0, 0, 50, 1, 2, 3}
	if _, err := DecryptStream(a, base, bytes.NewReader(short), io.Discard, false, 0); err == nil || !strings.Contains(err.Error(), "read chunk data") {
		t.Errorf("truncated chunk body: %v", err)
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestEncryptStreamWriteErrors(t *testing.T) {
	a := newTestAEAD(t, config.CipherChaCha20Poly1305)
	base, _ := GenerateNonce(a)
	for after, want := range map[int]string{0: "write chunk length", 1: "write chunk data", 2: "write EOF sentinel"} {
		_, err := EncryptStream(a, base, config.ChunkSizeLow, bytes.NewReader([]byte("data")), &failWriter{after: after}, false, 4)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("writer failing after %d writes: %v, want %q", after, err, want)
		}
	}
	var out bytes.Buffer
	_, err := EncryptStream(a, base, config.ChunkSizeLow, iotest.ErrReader(errors.New("EIO")), &out, false, 4)
	if err == nil || !strings.Contains(err.Error(), "read plaintext") {
		t.Errorf("read error: %v", err)
	}
	// DecryptStream: failing writer and a reader error inside the length prefix.
	ct := sealChunks(a, base, [][]byte{[]byte("abc")}, true)
	if _, err := DecryptStream(a, base, bytes.NewReader(ct), &failWriter{}, false, 0); err == nil || !strings.Contains(err.Error(), "write plaintext") {
		t.Errorf("decrypt to failing writer: %v", err)
	}
	if _, err := DecryptStream(a, base, iotest.ErrReader(errors.New("EIO")), io.Discard, false, 0); err == nil || !strings.Contains(err.Error(), "read chunk length") {
		t.Errorf("decrypt read error: %v", err)
	}
}

func TestStreamProgressBars(t *testing.T) {
	silenceStderr(t)
	a := newTestAEAD(t, config.CipherAES256GCM)
	base, _ := GenerateNonce(a)
	pt := make([]byte, 100000)
	var ct, back bytes.Buffer
	if _, err := EncryptStream(a, base, 4096, bytes.NewReader(pt), &ct, true, int64(len(pt))); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptStream(a, base, &ct, &back, true, int64(ct.Len())); err != nil || back.Len() != len(pt) {
		t.Fatal(err)
	}
}

func TestNewAEADErrors(t *testing.T) {
	if _, err := NewAEAD(make([]byte, 32), 0x03); !errors.Is(err, ErrInvalidCipher) {
		t.Errorf("unknown cipher: %v", err)
	}
	for _, id := range ciphers {
		for _, n := range []int{0, 16, 24, 31, 33} { // 16/24 would silently be AES-128/192
			if _, err := NewAEAD(make([]byte, n), id); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("%s with a %d-byte key: %v", id, n, err)
			}
		}
	}
	for _, id := range ciphers {
		a, err := NewAEAD(make([]byte, 32), id)
		if err != nil || a.NonceSize() != id.NonceSize() || a.Overhead() != 16 {
			t.Errorf("%s: nonce %d overhead %d err %v", id, a.NonceSize(), a.Overhead(), err)
		}
	}
}

func TestOpenRejectsWrongNonceAndKey(t *testing.T) {
	for _, id := range ciphers {
		a := newTestAEAD(t, id)
		ct, nonce, err := Seal(a, []byte("metadata"))
		if err != nil {
			t.Fatal(err)
		}
		n2 := bytes.Clone(nonce)
		n2[0] ^= 1
		if _, err := Open(a, n2, ct); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("%s wrong nonce: %v", id, err)
		}
		if _, err := Open(newTestAEAD(t, id), nonce, ct); !errors.Is(err, ErrAuthFailed) {
			t.Errorf("%s wrong key: %v", id, err)
		}
	}
}

func TestDeriveKeyProperties(t *testing.T) {
	salt := make([]byte, config.SaltLen)
	k1 := DeriveKey([]byte("pw"), salt, true)
	k2 := DeriveKey([]byte("pw "), salt, true)
	k3 := DeriveKey(nil, salt, true)
	if len(k1) != 32 || bytes.Equal(k1, k2) || bytes.Equal(k1, k3) {
		t.Fatalf("keys: len %d, pw==pw+space %v, pw==empty %v", len(k1), bytes.Equal(k1, k2), bytes.Equal(k1, k3))
	}
	// Known answers from an independent implementation (OpenSSL 3.5.9):
	//   openssl kdf -keylen 32 -kdfopt pass:PW -kdfopt hexsalt:SALT -kdfopt iter:8 \
	//     -kdfopt memcost:65536 -kdfopt lanes:8 ARGON2ID
	// They pin the --low-memory parameters: changing t, m or p silently makes
	// every existing file undecryptable.
	kats := []struct {
		pw   string
		salt []byte
		want string
	}{
		{"pw", make([]byte, 64), "f263416b290d5b54c912e468cd691856b762e2fd8db821541bea770612820fa7"},
		{"pw-Live-123", func() []byte {
			s := make([]byte, 64)
			for i := range s {
				s[i] = byte(i)
			}
			return s
		}(), "622c62b0a2a043a31a619ea480daef3e9d4ed008ad8abbea4108398852dd4de8"},
	}
	for _, k := range kats {
		if got := hex.EncodeToString(DeriveKey([]byte(k.pw), k.salt, true)); got != k.want {
			t.Errorf("Argon2id(%q) = %s, OpenSSL says %s", k.pw, got, k.want)
		}
	}
}

func TestHMACStreamMatchesAndPropagatesErrors(t *testing.T) {
	key, salt := []byte("k"), []byte("salt")
	ct := make([]byte, 3*config.BufferSize+17)
	rand.Read(ct)
	m1 := ComputeHMAC(key, salt, ct, []byte("name"), []byte("hash"))
	m2, err := ComputeHMACStream(key, salt, iotest.HalfReader(bytes.NewReader(ct)), []byte("name"), []byte("hash"))
	if err != nil || !bytes.Equal(m1, m2) {
		t.Fatalf("stream HMAC differs or failed: %v", err)
	}
	// Field order matters: name and hash are not interchangeable.
	m3 := ComputeHMAC(key, salt, ct, []byte("hash"), []byte("name"))
	if bytes.Equal(m1, m3) {
		t.Fatal("swapping encFilename and encHash must change the HMAC")
	}
	if err := VerifyHMACStream(key, salt, m1, iotest.ErrReader(errors.New("EIO")), nil, nil); err == nil || errors.Is(err, ErrHMACMismatch) {
		t.Fatalf("reader error must be reported as such, got %v", err)
	}
	if err := VerifyHMAC(key, salt, m1[:63], ct, []byte("name"), []byte("hash")); !errors.Is(err, ErrHMACMismatch) {
		t.Fatalf("truncated MAC accepted: %v", err)
	}
}

func TestNonceFieldPadding(t *testing.T) {
	for _, id := range ciphers {
		n := make([]byte, id.NonceSize())
		rand.Read(n)
		f := EncodeNonce(n)
		if !bytes.Equal(DecodeNonce(f[:], id), n) {
			t.Fatalf("%s round trip", id)
		}
		for i := 0; i < config.NonceFieldLen-len(n); i++ {
			if f[i] != 0 {
				t.Fatalf("%s: padding byte %d = %#x", id, i, f[i])
			}
		}
	}
	if got := DecodeNonce(make([]byte, 24), 0x03); len(got) != 0 {
		t.Fatalf("unknown cipher must decode to an empty nonce, got %d bytes", len(got))
	}
}
