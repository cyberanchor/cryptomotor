//go:build windows

package fileproc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cryptomotor/internal/config"
)

// CM-19: a Windows name of 255 UTF-16 units can need more than 255 UTF-8
// bytes; 3.1.0 refused to encrypt it.
func TestLongUnicodeNameWindows(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("я", 200) + ".txt" // 204 UTF-16 units, 404 UTF-8 bytes
	in := mustWrite(t, filepath.Join(dir, name), []byte("long name"))
	enc, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptFile(enc, filepath.Join(dir, "dec"), []byte("pw"), lowOpts(0))
	if err != nil || filepath.Base(dec) != name {
		t.Fatalf("%q %v", dec, err)
	}
}

// CM-19: on error paths the output is closed before it is removed, so no
// partial file stays behind on Windows.
func TestNoPartialFileAfterErrorWindows(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "a.txt"), []byte("partial"))
	enc, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherAES256GCM))
	if err != nil {
		t.Fatal(err)
	}
	flip(t, enc, int64(config.SystemBlockOffsets.NoncePayload+23)) // fails in DecryptStream
	out := filepath.Join(dir, "dec")
	if _, err := DecryptFile(enc, out, []byte("pw"), lowOpts(0)); err == nil {
		t.Fatal("tampered file accepted")
	}
	if names, _ := os.ReadDir(out); len(names) != 0 {
		t.Fatalf("left behind: %v", names)
	}
}
