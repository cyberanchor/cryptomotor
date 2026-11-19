package fileproc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"cryptomotor/internal/config"
	"cryptomotor/internal/crypto"
)

var allCiphers = []config.CipherID{config.CipherAES256GCM, config.CipherChaCha20Poly1305}

func lowOpts(id config.CipherID) Options { return Options{CipherID: id, LowMemory: true} }

// TestMain pretends the machine has 1 GiB free, so no test can start a real
// 4 GiB Argon2id derivation, even on a CI runner with plenty of RAM.
func TestMain(m *testing.M) {
	availableMemory = func() (uint64, bool) { return 1 << 30, true }
	os.Exit(m.Run())
}

func mustWrite(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

// captureStdout runs fn with os.Stdout redirected and returns the output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// craft writes a file exactly like EncryptFile but with a caller-chosen stored
// name and OrigNameLen: what anybody who knows the password can produce.
func craft(t *testing.T, path string, password []byte, id config.CipherID, name string, origLen uint32, plaintext []byte) {
	t.Helper()
	salt, _ := crypto.GenerateSalt()
	key := crypto.DeriveKey(password, salt, true)
	aead, err := crypto.NewAEAD(key, id)
	if err != nil {
		t.Fatal(err)
	}
	np, _ := crypto.GenerateNonce(aead)
	var stream bytes.Buffer
	if _, err := crypto.EncryptStream(aead, np, config.ChunkSizeLow, bytes.NewReader(plaintext), &stream, false, int64(len(plaintext))); err != nil {
		t.Fatal(err)
	}
	padded := make([]byte, config.PaddedFilenameLen)
	copy(padded, name)
	encName, nf, _ := crypto.Seal(aead, padded)
	sum := sha512.Sum512(plaintext)
	encHash, nh, _ := crypto.Seal(aead, sum[:])
	mac := crypto.ComputeHMAC(key, salt, stream.Bytes(), encName, encHash)
	hdr := buildSystemBlock(id, config.KDFLowMemory, salt, np, nf, nh, mac, encName, encHash, origLen)
	mustWrite(t, path, append(hdr, stream.Bytes()...))
}

// patch overwrites bytes of a file in place.
func patch(t *testing.T, path string, off int64, b ...byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

func flip(t *testing.T, path string, off int64) {
	t.Helper()
	data, _ := os.ReadFile(path)
	patch(t, path, off, data[off]^0xff)
}

// --- compatibility -----------------------------------------------------------

// Files written by the published v3.1.0 binary (--low-memory) must keep decrypting.
func TestGoldenV310Files(t *testing.T) {
	want, err := os.ReadFile("testdata/golden.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"xchacha", "aes", "xchacha-noflag", "aes-noflag"} {
		out := t.TempDir()
		opts := lowOpts(0)
		if strings.HasSuffix(c, "-noflag") {
			opts.LowMemory = false // CM-04: the 64 MiB setting is tried first
			c = strings.TrimSuffix(c, "-noflag")
		}
		got, err := DecryptFile("testdata/v310_"+c+".cm", out, []byte("golden-pw"), opts)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		data, _ := os.ReadFile(got)
		if filepath.Base(got) != "golden.txt" || !bytes.Equal(data, want) {
			t.Fatalf("%s: decrypted %s (%d bytes)", c, got, len(data))
		}
	}
}

// --- round trips and layout -------------------------------------------------

func TestRoundTripAndLayout(t *testing.T) {
	hexName := regexp.MustCompile(`^[0-9a-f]{32}$`)
	for _, id := range allCiphers {
		for _, size := range []int{0, 4, 17, 1<<20 + 7} {
			dir := t.TempDir()
			plain := randBytes(size)
			in := mustWrite(t, filepath.Join(dir, "in put.bin"), plain)
			encPath, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(id))
			if err != nil {
				t.Fatalf("%s/%d: %v", id, size, err)
			}
			raw, _ := os.ReadFile(encPath)
			o := config.SystemBlockOffsets
			switch {
			case !hexName.MatchString(filepath.Base(encPath)):
				t.Errorf("output name %q", filepath.Base(encPath))
			case len(raw) != config.SystemBlockLen+size+20*((size+config.ChunkSizeLow-1)/config.ChunkSizeLow)+4:
				t.Errorf("%s/%d: file size %d", id, size, len(raw))
			case string(raw[:8]) != config.Signature || raw[o.CipherID] != byte(id) || raw[o.KDFMode] != byte(config.KDFLowMemory):
				t.Errorf("%s/%d: header prefix % x", id, size, raw[:10])
			case binary.BigEndian.Uint32(raw[o.FilenameLen:]) != config.PaddedFilenameLen:
				t.Errorf("enc filename length field %d", binary.BigEndian.Uint32(raw[o.FilenameLen:]))
			case binary.BigEndian.Uint32(raw[o.OrigNameLen:]) != uint32(len("in put.bin")):
				t.Errorf("OrigNameLen %d", binary.BigEndian.Uint32(raw[o.OrigNameLen:]))
			}
			if id == config.CipherAES256GCM {
				for _, f := range []int{o.NoncePayload, o.NonceFilename, o.NonceHash} {
					if !bytes.Equal(raw[f:f+12], make([]byte, 12)) {
						t.Errorf("AES nonce field at %d not left-padded with zeros", f)
					}
				}
			}
			decPath, err := DecryptFile(encPath, filepath.Join(dir, "dec"), []byte("pw"), lowOpts(0))
			if err != nil {
				t.Fatalf("%s/%d decrypt: %v", id, size, err)
			}
			got, _ := os.ReadFile(decPath)
			if filepath.Base(decPath) != "in put.bin" || !bytes.Equal(got, plain) {
				t.Fatalf("%s/%d: round trip mismatch (%s)", id, size, decPath)
			}
			if names := entries(t, filepath.Join(dir, "dec")); len(names) != 1 {
				t.Fatalf("leftovers in output dir: %v", names)
			}
			for path, want := range map[string]os.FileMode{filepath.Join(dir, "enc"): 0o750, encPath: 0o640, decPath: 0o600} {
				st, _ := os.Stat(path)
				if runtime.GOOS != "windows" && st.Mode().Perm()&^want != 0 {
					t.Errorf("%s mode %o exceeds %o", path, st.Mode().Perm(), want)
				}
			}
		}
	}
}

func TestEncryptionIsRandomized(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "same.txt"), []byte("same content"))
	a, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherAES256GCM))
	b, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherAES256GCM))
	ra, _ := os.ReadFile(a)
	rb, _ := os.ReadFile(b)
	o := config.SystemBlockOffsets
	if a == b || bytes.Equal(ra[o.Salt:o.Salt+64], rb[o.Salt:o.Salt+64]) || bytes.Equal(ra[config.SystemBlockLen:], rb[config.SystemBlockLen:]) {
		t.Fatal("two encryptions share name, salt or ciphertext")
	}
	h1, _ := readSystemBlock(a)
	for _, pair := range [][2][]byte{{h1.noncePayload, h1.nonceFilename}, {h1.nonceFilename, h1.nonceHash}, {h1.noncePayload, h1.nonceHash}} {
		if bytes.Equal(pair[0], pair[1]) {
			t.Fatal("the three per-file nonces must differ")
		}
	}
}

func TestDecryptUsesCipherFromHeader(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "a.txt"), []byte("cipher from header"))
	enc, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherAES256GCM))
	if _, err := DecryptFile(enc, filepath.Join(dir, "dec"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); err != nil {
		t.Fatalf("opts.CipherID must not matter on decrypt: %v", err)
	}
}

func TestNamesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	names := []string{strings.Repeat("я", 125) + ".txt", "-rf", "dots.in.name", "a'b$(id).txt"}
	if runtime.GOOS != "windows" { // not valid file names on Windows
		names = append(names, "new\nline", `back\slash`, " lead and trail ", "\x1b[31mred", `quote"d`)
	}
	for _, name := range names {
		in := mustWrite(t, filepath.Join(dir, "src", name), []byte("name test"))
		enc, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305))
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		dec, err := DecryptFile(enc, filepath.Join(dir, "dec"), []byte("pw"), lowOpts(0))
		if err != nil || filepath.Base(dec) != name {
			t.Fatalf("%q -> %q, %v", name, filepath.Base(dec), err)
		}
	}
}

// --- header parsing ------------------------------------------------------------

func TestSystemBlockBuildParse(t *testing.T) {
	for _, id := range allCiphers {
		n := id.NonceSize()
		salt, np, nf, nh := randBytes(64), randBytes(n), randBytes(n), randBytes(n)
		mac, en, eh := randBytes(64), randBytes(512), randBytes(80)
		raw := buildSystemBlock(id, config.KDFStandard, salt, np, nf, nh, mac, en, eh, 42)
		if len(raw) != config.SystemBlockLen {
			t.Fatalf("header length %d", len(raw))
		}
		p := mustWrite(t, filepath.Join(t.TempDir(), "h"), raw)
		h, err := readSystemBlock(p)
		if err != nil {
			t.Fatal(err)
		}
		if h.cipherID != id || h.kdf != config.KDFStandard || !bytes.Equal(h.salt, salt) || !bytes.Equal(h.noncePayload, np) ||
			!bytes.Equal(h.nonceFilename, nf) || !bytes.Equal(h.nonceHash, nh) || !bytes.Equal(h.hmac, mac) ||
			!bytes.Equal(h.encFilename, en) || !bytes.Equal(h.encHash, eh) || h.origNameLen != 42 || !bytes.Equal(h.raw, raw) {
			t.Fatalf("%s: parsed header differs", id)
		}
	}
}

func TestReadSystemBlockErrors(t *testing.T) {
	dir := t.TempDir()
	valid := buildSystemBlock(config.CipherChaCha20Poly1305, config.KDFLowMemory, randBytes(64), randBytes(24), randBytes(24), randBytes(24), randBytes(64), randBytes(512), randBytes(80), 1)
	o := config.SystemBlockOffsets
	with := func(off int, b ...byte) []byte { r := bytes.Clone(valid); copy(r[off:], b); return r }
	aesHdr := buildSystemBlock(config.CipherAES256GCM, config.KDFLowMemory, randBytes(64), randBytes(12), randBytes(12), randBytes(12), randBytes(64), randBytes(512), randBytes(80), 1)
	cases := []struct {
		name string
		data []byte
		want error
		text string
	}{
		{"short", valid[:809], ErrFileTooShort, ""},
		{"empty", nil, ErrFileTooShort, ""},
		{"v2", append([]byte(config.OldSignature), valid[8:]...), ErrOldFormat, ""},
		{"bad sig", append([]byte("CMv4\x00\x00\x00\x00"), valid[8:]...), ErrBadSignature, ""},
		{"cipher 0", append(append([]byte(config.Signature), 0x00), valid[9:]...), ErrBadHeader, "unknown cipher ID 0x00"},
		{"kdf 3", with(o.KDFMode, 0x03), ErrBadHeader, "unknown key derivation mode 0x03"},
		{"padded len", with(o.FilenameLen, 0, 0, 2, 0), ErrBadHeader, "padded name length field is 512"},
		{"name len 497", with(o.OrigNameLen, 0, 0, 1, 0xf1), ErrBadHeader, "name length field is 497"},
		{"aes padding", func() []byte { r := bytes.Clone(aesHdr); r[o.NonceHash] = 1; return r }(), ErrBadHeader, "unused nonce bytes"},
	}
	for _, c := range cases {
		p := mustWrite(t, filepath.Join(dir, c.name), c.data)
		_, err := readSystemBlock(p)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := readSystemBlock(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file parsed")
	}
	if s, err := peekSignature(mustWrite(t, filepath.Join(dir, "3"), []byte("CMv"))); err == nil {
		t.Errorf("peekSignature of a 3-byte file: %q", s)
	}
}

// --- tampering and failures ----------------------------------------------------

func TestTamperedFilesRejected(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "secret.txt"), randBytes(3000))
	base, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305))
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(base)
	o := config.SystemBlockOffsets
	cases := []struct {
		name   string
		mutate func(p string)
		want   error
	}{
		{"salt", func(p string) { flip(t, p, int64(o.Salt)) }, crypto.ErrHMACMismatch},
		{"hmac", func(p string) { flip(t, p, int64(o.HMAC+63)) }, crypto.ErrHMACMismatch},
		{"enc filename", func(p string) { flip(t, p, int64(o.EncFilename+511)) }, crypto.ErrHMACMismatch},
		{"enc hash", func(p string) { flip(t, p, int64(o.EncHash)) }, crypto.ErrHMACMismatch},
		{"payload", func(p string) { flip(t, p, int64(config.SystemBlockLen+10)) }, crypto.ErrHMACMismatch},
		{"length prefix", func(p string) { flip(t, p, int64(config.SystemBlockLen+3)) }, crypto.ErrHMACMismatch},
		{"truncated", func(p string) { os.Truncate(p, int64(len(orig)-1)) }, crypto.ErrHMACMismatch},
		{"appended", func(p string) { f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0); f.Write([]byte{0}); f.Close() }, crypto.ErrHMACMismatch},
		{"nonce filename", func(p string) { flip(t, p, int64(o.NonceFilename+23)) }, crypto.ErrAuthFailed},
		{"nonce hash", func(p string) { flip(t, p, int64(o.NonceHash+23)) }, crypto.ErrAuthFailed},
		{"nonce payload", func(p string) { flip(t, p, int64(o.NoncePayload+23)) }, crypto.ErrAuthFailed},
		// XChaCha uses all 24 nonce bytes, so as an AES header the padding is not zero.
		{"cipher swap", func(p string) { patch(t, p, int64(o.CipherID), byte(config.CipherAES256GCM)) }, ErrBadHeader},
		{"kdf unknown", func(p string) { patch(t, p, int64(o.KDFMode), 0x07) }, ErrBadHeader},
		{"kdf 64 MiB -> 4 GiB", func(p string) { patch(t, p, int64(o.KDFMode), byte(config.KDFStandard)) }, ErrNotEnoughMemory},
		{"padded name len", func(p string) { patch(t, p, int64(o.FilenameLen+3), 0) }, ErrBadHeader},
		{"name len shorter", func(p string) { patch(t, p, int64(o.OrigNameLen+3), 3) }, ErrBadHeader},
		{"name len longer", func(p string) { patch(t, p, int64(o.OrigNameLen+3), 14) }, ErrBadHeader},
		{"name len zero", func(p string) { patch(t, p, int64(o.OrigNameLen+3), 0) }, ErrBadHeader},
		{"name len 0xffffffff", func(p string) { patch(t, p, int64(o.OrigNameLen), 0xff, 0xff, 0xff, 0xff) }, ErrBadHeader},
		{"signature", func(p string) { flip(t, p, 3) }, ErrBadSignature},
	}
	for _, c := range cases {
		p := filepath.Join(dir, "case.cm")
		mustWrite(t, p, orig)
		c.mutate(p)
		out := filepath.Join(dir, "out-"+strings.ReplaceAll(c.name, " ", "_"))
		_, err := DecryptFile(p, out, []byte("pw"), lowOpts(0))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if names := entries(t, out); len(names) != 0 {
			t.Errorf("%s: files left behind: %v", c.name, names)
		}
	}
}

func TestWrongPasswordLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "a.txt"), []byte("wrong password test"))
	enc, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("right"), lowOpts(config.CipherChaCha20Poly1305))
	for _, pw := range []string{"wrong", "right ", "Right", "righ"} {
		if _, err := DecryptFile(enc, filepath.Join(dir, "dec"), []byte(pw), lowOpts(0)); !errors.Is(err, crypto.ErrHMACMismatch) {
			t.Errorf("password %q: %v", pw, err)
		}
	}
	if names := entries(t, filepath.Join(dir, "dec")); len(names) != 0 {
		t.Fatalf("output after failed decrypts: %v", names)
	}
}

func TestEncryptFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := EncryptFile(filepath.Join(dir, "missing"), dir, []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); err == nil {
		t.Error("missing input accepted")
	}
	// A directory is refused before the key derivation, and nothing is created.
	sub := filepath.Join(dir, "subdir")
	os.MkdirAll(filepath.Join(sub, "x"), 0o750)
	if _, err := EncryptFile(sub, filepath.Join(dir, "enc1"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory input: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "enc1")); !os.IsNotExist(err) {
		t.Errorf("output dir created for a refused input")
	}
	in := mustWrite(t, filepath.Join(dir, "in.txt"), []byte("abcdef"))
	blocker := mustWrite(t, filepath.Join(dir, "blocker"), []byte("x"))
	if _, err := EncryptFile(in, blocker, []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); err == nil || !strings.Contains(err.Error(), "create output dir") {
		t.Errorf("output dir is a file: %v", err)
	}
	if _, err := EncryptFile(in, dir, []byte("pw"), lowOpts(0x07)); !errors.Is(err, crypto.ErrInvalidCipher) {
		t.Errorf("invalid cipher: %v", err)
	}
	unreadable := mustWrite(t, filepath.Join(dir, "unreadable"), []byte("secret"))
	os.Chmod(unreadable, 0)
	defer os.Chmod(unreadable, 0o600)
	if _, err := EncryptFile(unreadable, filepath.Join(dir, "enc2"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); err == nil {
		if os.Geteuid() != 0 && runtime.GOOS != "windows" {
			t.Error("unreadable input accepted")
		}
	} else if _, statErr := os.Stat(filepath.Join(dir, "enc2")); !os.IsNotExist(statErr) {
		t.Error("output dir created although the input could not be opened")
	}
}

func TestStreamFailureRemovesTempFile(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "a.bin"), randBytes(5000))
	enc, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherAES256GCM))
	// The payload nonce is not covered by HMAC, so this fails only in DecryptStream,
	// after the temp file exists.
	flip(t, enc, int64(config.SystemBlockOffsets.NoncePayload+23))
	out := filepath.Join(dir, "dec")
	if _, err := DecryptFile(enc, out, []byte("pw"), lowOpts(0)); !errors.Is(err, crypto.ErrAuthFailed) || !strings.Contains(err.Error(), "stream decrypt") {
		t.Fatalf("err = %v", err)
	}
	if names := entries(t, out); len(names) != 0 {
		t.Fatalf("temp file left: %v", names)
	}
}

func TestDryRun(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "d.txt"), []byte("dry run data"))
	opts := lowOpts(config.CipherChaCha20Poly1305)
	opts.DryRun = true
	p, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), opts)
	if err != nil || filepath.Dir(p) != filepath.Join(dir, "enc") {
		t.Fatalf("dry-run encrypt: %q %v", p, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote %s", p)
	}
	real, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305))
	got, err := DecryptFile(real, filepath.Join(dir, "dec"), []byte("pw"), opts)
	if err != nil || got != filepath.Join(dir, "dec", "d.txt") {
		t.Fatalf("dry-run decrypt: %q %v", got, err)
	}
	if names := entries(t, filepath.Join(dir, "dec")); len(names) != 0 {
		t.Fatalf("dry-run decrypt wrote %v", names)
	}
	if _, err := DecryptFile(real, filepath.Join(dir, "dec"), []byte("bad"), opts); !errors.Is(err, crypto.ErrHMACMismatch) {
		t.Fatalf("dry-run with wrong password: %v", err)
	}
}

// --- folders ---------------------------------------------------------------------

func TestProcessFolderEndToEnd(t *testing.T) {
	dir := t.TempDir()
	want := map[string][]byte{"a.txt": randBytes(100), "b.bin": randBytes(70000), ".hidden": randBytes(10)}
	for n, d := range want {
		mustWrite(t, filepath.Join(dir, n), d)
	}
	mustWrite(t, filepath.Join(dir, "empty"), nil) // empty files are fine
	want["empty"] = nil
	mustWrite(t, filepath.Join(dir, "nested", "inner.txt"), []byte("nested file")) // not recursed
	opts := lowOpts(config.CipherChaCha20Poly1305)
	if err := ProcessFolder(dir, []byte("pw"), "encrypt", opts); err != nil {
		t.Fatal(err)
	}
	encDir := filepath.Join(dir, "encrypted")
	if n := len(entries(t, encDir)); n != len(want) {
		t.Fatalf("%d encrypted files, want %d", n, len(want))
	}
	mustWrite(t, filepath.Join(encDir, "notes.txt"), []byte("plain, must be skipped"))
	mustWrite(t, filepath.Join(encDir, "abc"), []byte("CMv")) // shorter than a signature
	if err := ProcessFolder(encDir, []byte("pw"), "decrypt", opts); err != nil {
		t.Fatal(err)
	}
	decDir := filepath.Join(encDir, "decrypted")
	for n, d := range want {
		got, err := os.ReadFile(filepath.Join(decDir, n))
		if err != nil || !bytes.Equal(got, d) || (d == nil && len(got) != 0) {
			t.Errorf("%s: %v", n, err)
		}
	}
	if n := len(entries(t, decDir)); n != len(want) {
		t.Errorf("decrypted dir holds %d files: %v", n, entries(t, decDir))
	}
	if err := ProcessFolder(filepath.Join(dir, "missing"), []byte("pw"), "encrypt", opts); err == nil {
		t.Error("missing folder accepted")
	}
}

// --- analyze and helpers -----------------------------------------------------------

func TestAnalyzeOutput(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "report.pdf"), randBytes(1234))
	enc, _ := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherAES256GCM))
	out := captureStdout(t, func() {
		if err := AnalyzeFile(enc, true); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"Cipher:         AES-256-GCM", "Payload:        1258 bytes", "System block:   810 bytes",
		"Key derivation: Argon2id 64 MiB (--low-memory)", "CipherID:        0x01 (AES-256-GCM)",
		"KDF mode:        0x01", "Padded name len: 496", "Orig name len:   10 bytes"} {
		if !strings.Contains(out, want) {
			t.Errorf("analyze output lacks %q\n%s", want, out)
		}
	}
	// CM-09: the summary no longer advertises the name length.
	plain := captureStdout(t, func() { AnalyzeFile(enc, false) })
	if strings.Contains(plain, "name") {
		t.Errorf("--analyze without --debug mentions the name: %s", plain)
	}
	if err := AnalyzeFile(in, false); !errors.Is(err, ErrBadSignature) {
		t.Errorf("plain file: %v", err)
	}
}

func TestRandomFilename(t *testing.T) {
	seen := map[string]bool{}
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	for i := 0; i < 2000; i++ {
		n := randomFilename()
		if !re.MatchString(n) || seen[n] {
			t.Fatalf("bad or repeated name %q", n)
		}
		seen[n] = true
	}
}

func TestCraftHelperMatchesEncryptFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.cm")
	craft(t, p, []byte("pw"), config.CipherChaCha20Poly1305, "normal.txt", 10, []byte("crafted payload"))
	got, err := DecryptFile(p, filepath.Join(dir, "dec"), []byte("pw"), lowOpts(0))
	if err != nil || filepath.Base(got) != "normal.txt" {
		t.Fatalf("crafted file must decrypt like a normal one: %q %v", got, err)
	}
}
