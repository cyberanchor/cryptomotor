package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"cryptomotor/internal/config"
)

// countingReader counts how many bytes the decoder pulled from the stream.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// CM-07: a chunk longer than ChunkSize plus the tag (or too short to hold a
// tag) is rejected after its 4-byte length, before anything is allocated or
// read for it. A crafted 0xffffffff used to allocate 4 GiB.
func TestDecryptStreamBoundsChunkLength(t *testing.T) {
	a := newTestAEAD(t, config.CipherChaCha20Poly1305)
	base, _ := GenerateNonce(a)
	for _, declared := range []uint32{config.ChunkSize + 17, 0xffffffff, 1, 16} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], declared)
		cr := &countingReader{r: io.MultiReader(bytes.NewReader(prefix[:]), io.LimitReader(zeros{}, 1<<20))}
		_, err := DecryptStream(a, base, cr, io.Discard, false, 0)
		if !errors.Is(err, ErrStreamFormat) {
			t.Errorf("length %d: err = %v, want ErrStreamFormat", declared, err)
		}
		if cr.n != 4 {
			t.Errorf("length %d: decoder read %d bytes, want only the 4-byte prefix", declared, cr.n)
		}
	}
	// The largest legitimate chunk is still accepted.
	pt := make([]byte, config.ChunkSize)
	stream := sealChunks(a, base, [][]byte{pt}, true)
	if n, err := DecryptStream(a, base, bytes.NewReader(stream), io.Discard, false, 0); err != nil || n != config.ChunkSize {
		t.Fatalf("full-size chunk: %d %v", n, err)
	}
}

// CM-24: the stream must end with the zero-length record and nothing may
// follow it. Truncation exactly at a chunk boundary with a new end record is
// indistinguishable from a shorter file at this level; DecryptFile catches it
// through HMAC and the plaintext SHA-512 (TestTruncatedAtChunkBoundary).
func TestDecryptStreamRequiresEndRecord(t *testing.T) {
	a := newTestAEAD(t, config.CipherChaCha20Poly1305)
	base, _ := GenerateNonce(a)
	chunks := [][]byte{[]byte("first chunk "), []byte("second chunk "), []byte("last chunk")}
	cases := map[string][]byte{
		"end record missing":                sealChunks(a, base, chunks, false),
		"two stray bytes instead of record": append(sealChunks(a, base, chunks, false), 0, 0),
		"data after the end record":         append(sealChunks(a, base, chunks, true), 'x'),
		"empty stream":                      nil,
	}
	for name, stream := range cases {
		var out bytes.Buffer
		if _, err := DecryptStream(a, base, bytes.NewReader(stream), &out, false, 0); !errors.Is(err, ErrStreamFormat) {
			t.Errorf("%s: err = %v (output %q)", name, err, out.String())
		}
	}
	var out bytes.Buffer
	if _, err := DecryptStream(a, base, bytes.NewReader(sealChunks(a, base, chunks, true)), &out, false, 0); err != nil ||
		out.String() != "first chunk second chunk last chunk" {
		t.Fatalf("well-formed stream: %q %v", out.String(), err)
	}
}
