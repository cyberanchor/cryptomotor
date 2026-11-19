package fileproc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cryptomotor/internal/config"
	"cryptomotor/internal/crypto"
)

// Regression tests for the findings of the 2026-11-19 audit (CM-xx).

// decryptNoPanic turns a panic inside DecryptFile into a test failure.
func decryptNoPanic(t *testing.T, enc, out string, opts Options) (path string, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DecryptFile panicked: %v", r)
		}
	}()
	return DecryptFile(enc, out, []byte("pw"), opts)
}

func encryptLow(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	in := mustWrite(t, filepath.Join(dir, "src", name), data)
	enc, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// CM-01: a stored name never leaves the output directory.
func TestStoredNameCannotEscape(t *testing.T) {
	names := []string{"../../victim.txt", "..", ".", "a/b.txt", "/etc/passwd", "../victim.txt"}
	if runtime.GOOS == "windows" {
		names = append(names, `..\..\victim.txt`, `a\b.txt`, "CON", "C:victim.txt", "file.txt:stream")
	}
	for i, name := range names {
		dir := t.TempDir()
		victim := mustWrite(t, filepath.Join(dir, "victim.txt"), []byte("original content"))
		enc := filepath.Join(dir, "inbox", "evil.cm")
		craft(t, enc, []byte("pw"), config.CipherChaCha20Poly1305, name, uint32(len(name)), []byte("written by a crafted file"))
		out := filepath.Join(dir, "inbox", "decrypted")
		_, err := decryptNoPanic(t, enc, out, lowOpts(0))
		if !errors.Is(err, ErrUnsafeName) {
			t.Errorf("%d %q: err = %v, want ErrUnsafeName", i, name, err)
		}
		if data, _ := os.ReadFile(victim); string(data) != "original content" {
			t.Errorf("%q: victim changed to %q", name, data)
		}
		if names := entries(t, out); len(names) != 0 {
			t.Errorf("%q: output dir not empty: %v", name, names)
		}
	}
}

func TestCheckStoredName(t *testing.T) {
	ok := []string{"report.pdf", "-rf", ".env", "документ 密码.txt", "a b", strings.Repeat("x", 255)}
	bad := []string{"", ".", "..", "a/b", "/x", "../x", "x\x00y"}
	if runtime.GOOS == "windows" {
		bad = append(bad, `a\b`, `..\x`, "NUL", "CON", "C:x", "x:y") // "con.txt" is a valid name since Windows 11
	} else {
		ok = append(ok, `a\b`, `..\..\evil.bat`, "new\nline") // legal Linux names
	}
	for _, n := range ok {
		if err := checkStoredName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := checkStoredName(n); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("%q accepted", n)
		}
	}
}

// CM-02: an existing output file is kept unless --force is given.
func TestDecryptKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	enc := encryptLow(t, dir, "notes.txt", []byte("old backup"))
	existing := mustWrite(t, filepath.Join(dir, "dec", "notes.txt"), []byte("newer work"))
	if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), lowOpts(0)); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("err = %v, want ErrOutputExists", err)
	}
	if data, _ := os.ReadFile(existing); string(data) != "newer work" {
		t.Fatalf("existing file replaced: %q", data)
	}
	if names := entries(t, filepath.Join(dir, "dec")); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
	opts := lowOpts(0)
	opts.Force = true
	if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), opts); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if data, _ := os.ReadFile(existing); string(data) != "old backup" {
		t.Fatalf("--force did not replace: %q", data)
	}
	// A directory with the target name is never replaced, not even with --force.
	os.Remove(existing)
	os.Mkdir(existing, 0o750)
	for _, force := range []bool{false, true} {
		opts.Force = force
		if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), opts); err == nil {
			t.Fatalf("force=%v: replaced a directory", force)
		}
	}
}

func TestPublishNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	tmp := mustWrite(t, filepath.Join(dir, "x.tmp"), []byte("new"))
	final := mustWrite(t, filepath.Join(dir, "final"), []byte("old"))
	if err := publish(tmp, final, false); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("err = %v", err)
	}
	if data, _ := os.ReadFile(final); string(data) != "old" {
		t.Fatal("replaced")
	}
	fresh := filepath.Join(dir, "fresh")
	if err := publish(tmp, fresh, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temp file left after publish")
	}
	if data, _ := os.ReadFile(fresh); string(data) != "new" {
		t.Fatal("content")
	}
}

// CM-02: duplicates in one folder: the first is kept, the second fails, and
// ProcessFolder reports it.
func TestFolderDecryptDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	inbox := filepath.Join(dir, "inbox")
	for i, content := range []string{"from laptop", "from phone"} {
		src := mustWrite(t, filepath.Join(dir, fmt.Sprint(i), "report.txt"), []byte(content))
		if _, err := EncryptFile(src, inbox, []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); err != nil {
			t.Fatal(err)
		}
	}
	err := ProcessFolder(inbox, []byte("pw"), "decrypt", lowOpts(0))
	if !errors.Is(err, ErrFolderFailures) || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("err = %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(inbox, "decrypted", "report.txt"))
	if s := string(data); s != "from laptop" && s != "from phone" {
		t.Fatalf("decrypted content %q", s)
	}
}

// CM-03: OrigNameLen is range-checked and cross-checked with the name.
func TestOrigNameLenChecked(t *testing.T) {
	for _, v := range []uint32{0, 3, 11, 14, 497, 0xffffffff} {
		dir := t.TempDir()
		enc := encryptLow(t, dir, "contract-1.pdf", []byte("name integrity")) // 14 bytes
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		patch(t, enc, int64(config.SystemBlockOffsets.OrigNameLen), b[:]...)
		_, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), lowOpts(0))
		if v == 14 {
			if err != nil {
				t.Fatalf("untouched length rejected: %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrBadHeader) {
			t.Errorf("OrigNameLen=%d: err = %v", v, err)
		}
	}
}

// CM-04: the Argon2id cost is recorded; old files work without the flag.
func TestKDFModeRecorded(t *testing.T) {
	dir := t.TempDir()
	enc := encryptLow(t, dir, "a.txt", []byte("kdf"))
	raw, _ := os.ReadFile(enc)
	if config.KDFMode(raw[config.SystemBlockOffsets.KDFMode]) != config.KDFLowMemory {
		t.Fatalf("mode byte %#x", raw[config.SystemBlockOffsets.KDFMode])
	}
	// No --low-memory needed to decrypt it.
	opts := lowOpts(0)
	opts.LowMemory = false
	if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), opts); err != nil {
		t.Fatal(err)
	}
}

func TestAutoFallbackToLowMemory(t *testing.T) {
	dir := t.TempDir()
	in := mustWrite(t, filepath.Join(dir, "a.txt"), []byte("fallback"))
	opts := lowOpts(config.CipherAES256GCM)
	opts.LowMemory = false // TestMain reports 1 GiB free: less than the 8 GiB threshold
	enc, err := EncryptFile(in, filepath.Join(dir, "enc"), []byte("pw"), opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(enc)
	if config.KDFMode(raw[config.SystemBlockOffsets.KDFMode]) != config.KDFLowMemory {
		t.Fatal("fallback not recorded")
	}
	if _, err := DecryptFile(enc, filepath.Join(dir, "dec"), []byte("pw"), opts); err != nil {
		t.Fatal(err)
	}
}

func TestChooseKDF(t *testing.T) {
	saved := availableMemory
	defer func() { availableMemory = saved }()
	cases := []struct {
		low   bool
		avail uint64
		known bool
		want  config.KDFMode
	}{
		{true, 64 << 30, true, config.KDFLowMemory},
		{false, 64 << 30, true, config.KDFStandard},
		{false, config.Argon2MemoryThreshold - 1, true, config.KDFLowMemory},
		{false, config.Argon2MemoryThreshold, true, config.KDFStandard},
		{false, 0, false, config.KDFStandard}, // unknown: keep the documented default
	}
	for _, c := range cases {
		availableMemory = func() (uint64, bool) { return c.avail, c.known }
		if got := chooseKDF(c.low); got != c.want {
			t.Errorf("chooseKDF(low=%v, avail=%d, known=%v) = %v, want %v", c.low, c.avail, c.known, got, c.want)
		}
	}
	availableMemory = func() (uint64, bool) { return 4 << 30, true }
	if err := checkMemoryForStandard(); !errors.Is(err, ErrNotEnoughMemory) {
		t.Errorf("4 GiB free must not be enough for a 4 GiB derivation plus headroom: %v", err)
	}
	availableMemory = func() (uint64, bool) { return 5 << 30, true }
	if err := checkMemoryForStandard(); err != nil {
		t.Errorf("5 GiB free: %v", err)
	}
}

// A file that records the 4 GiB cost is refused up front on a small machine,
// instead of swapping or being killed (TestMain reports 1 GiB free).
func TestStandardFileNeedsMemory(t *testing.T) {
	dir := t.TempDir()
	enc := encryptLow(t, dir, "a.txt", []byte("standard"))
	patch(t, enc, int64(config.SystemBlockOffsets.KDFMode), byte(config.KDFStandard))
	_, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), lowOpts(0))
	if !errors.Is(err, ErrNotEnoughMemory) || !strings.Contains(err.Error(), "MiB are available") {
		t.Fatalf("err = %v", err)
	}
}

// Files from 3.1.0: a wrong password reports that 4 GiB could not be tried.
func TestLegacyFileWrongPassword(t *testing.T) {
	opts := lowOpts(0)
	opts.LowMemory = false
	_, err := DecryptFile("testdata/v310_xchacha.cm", t.TempDir(), []byte("wrong"), opts)
	if !errors.Is(err, crypto.ErrHMACMismatch) || !errors.Is(err, ErrNotEnoughMemory) && !strings.Contains(err.Error(), "cannot be tried") {
		t.Fatalf("err = %v", err)
	}
	opts.LowMemory = true
	if _, err := DecryptFile("testdata/v310_xchacha.cm", t.TempDir(), []byte("wrong"), opts); !errors.Is(err, crypto.ErrHMACMismatch) {
		t.Fatalf("with --low-memory: %v", err)
	}
}

// CM-06: ProcessFolder reports failures.
func TestProcessFolderReportsFailures(t *testing.T) {
	dir := t.TempDir()
	encryptLow(t, dir, "a.txt", []byte("folder failure"))
	err := ProcessFolder(filepath.Join(dir, "enc"), []byte("wrong"), "decrypt", lowOpts(0))
	if !errors.Is(err, ErrFolderFailures) {
		t.Fatalf("err = %v", err)
	}
	if err := ProcessFolder(dir, []byte("pw"), "rot13", lowOpts(0)); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

// CM-14: --dry-run creates nothing.
func TestDryRunCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	real := encryptLow(t, dir, "d.txt", []byte("dry run"))
	opts := lowOpts(config.CipherChaCha20Poly1305)
	opts.DryRun = true
	if _, err := EncryptFile(filepath.Join(dir, "src", "d.txt"), filepath.Join(dir, "enc2"), []byte("pw"), opts); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptFile(real, filepath.Join(dir, "dec"), []byte("pw"), opts); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"enc2", "dec"} {
		if _, err := os.Stat(filepath.Join(dir, d)); err == nil {
			t.Errorf("dry run created %s/", d)
		}
	}
}

// CM-09 (kept for compatibility): OrigNameLen still holds the real length,
// because cryptomotor 3.1.0 needs it to decrypt files written by this
// version; --analyze no longer prints it (TestAnalyzeOutput).
func TestNameLengthKeptForCompatibility(t *testing.T) {
	dir := t.TempDir()
	name := "2026-payroll-all-employees.xlsx"
	enc := encryptLow(t, dir, name, []byte("length"))
	raw, _ := os.ReadFile(enc)
	if v := binary.BigEndian.Uint32(raw[config.SystemBlockOffsets.OrigNameLen:]); v != uint32(len(name)) {
		t.Fatalf("OrigNameLen = %d, 3.1.0 needs %d", v, len(name))
	}
}

// CM-17: the error names the byte.
func TestUnknownCipherErrorShowsByte(t *testing.T) {
	raw := buildSystemBlock(config.CipherChaCha20Poly1305, config.KDFLowMemory, make([]byte, 64), make([]byte, 24), make([]byte, 24), make([]byte, 24), make([]byte, 64), make([]byte, 512), make([]byte, 80), 1)
	raw[config.SystemBlockOffsets.CipherID] = 0x03
	p := mustWrite(t, filepath.Join(t.TempDir(), "x"), raw)
	_, err := readSystemBlock(p)
	if !errors.Is(err, ErrBadHeader) || !strings.Contains(err.Error(), "0x03") {
		t.Fatalf("error = %v, want it to name 0x03", err)
	}
}

// CM-23: header fields outside HMAC are validated.
func TestUnusedHeaderFieldsValidated(t *testing.T) {
	dir := t.TempDir()
	enc := encryptLow(t, dir, "a.txt", []byte("malleable header"))
	orig, _ := os.ReadFile(enc)
	o := config.SystemBlockOffsets
	for name, off := range map[string]int{"kdf": o.KDFMode, "padded name length": o.FilenameLen} {
		mustWrite(t, enc, bytes.Clone(orig))
		patch(t, enc, int64(off), 0x5a)
		if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec-"+name[:3]), lowOpts(0)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("modified %s field: %v", name, err)
		}
	}
	// 0x01 -> 0x00 makes it look like a 3.1.0 file: still the same key, still fine.
	mustWrite(t, enc, bytes.Clone(orig))
	patch(t, enc, int64(o.KDFMode), byte(config.KDFUnrecorded))
	if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec-legacy"), lowOpts(0)); err != nil {
		t.Errorf("legacy-marked file: %v", err)
	}
}

// CM-24: truncation exactly at a chunk boundary, with a new end record, is
// caught at file level.
func TestTruncatedAtChunkBoundary(t *testing.T) {
	dir := t.TempDir()
	enc := encryptLow(t, dir, "big.bin", randBytes(2*config.ChunkSizeLow+100)) // 3 chunks
	raw, _ := os.ReadFile(enc)
	cut := config.SystemBlockLen + 2*(4+config.ChunkSizeLow+16) // after chunk 1
	trunc := append(bytes.Clone(raw[:cut]), 0, 0, 0, 0)
	mustWrite(t, enc, trunc)
	if _, err := decryptNoPanic(t, enc, filepath.Join(dir, "dec"), lowOpts(0)); !errors.Is(err, crypto.ErrHMACMismatch) {
		t.Fatalf("err = %v", err)
	}
}

// CM-08: Abort removes partial outputs that are still open.
func TestAbortRemovesPartialFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.part")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("partial"))
	track(p, f)
	removed := Abort()
	if len(removed) != 1 || removed[0] != p {
		t.Fatalf("Abort removed %v", removed)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("partial file still there")
	}
	if len(Abort()) != 0 {
		t.Fatal("second Abort found files")
	}
}

// CM-15: an unreadable file in folder mode is a failure, not "skipped".
func TestFolderUnreadableIsFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dir := t.TempDir()
	enc := encryptLow(t, dir, "a.txt", []byte("readable"))
	locked := filepath.Join(filepath.Dir(enc), "locked.cm")
	data, _ := os.ReadFile(enc)
	mustWrite(t, locked, data)
	os.Chmod(locked, 0)
	defer os.Chmod(locked, 0o600)
	err := ProcessFolder(filepath.Dir(enc), []byte("pw"), "decrypt", lowOpts(0))
	if !errors.Is(err, ErrFolderFailures) || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("err = %v", err)
	}
}
