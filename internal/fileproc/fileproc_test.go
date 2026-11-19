package fileproc_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cryptomotor/internal/config"
	"cryptomotor/internal/fileproc"
	"cryptomotor/internal/logger"
)

func init() {
	// Suppress log output during tests.
	logger.Init("", false, false, false)
}

// quietOpts returns options suitable for silent testing.
func quietOpts(cipher config.CipherID) fileproc.Options {
	return fileproc.Options{
		CipherID:     cipher,
		LowMemory:    true, // fast tests
		ShowProgress: false,
	}
}

// TestEncryptDecryptRoundTrip verifies a full encrypt→decrypt cycle
// produces an identical file for both ciphers.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, cid := range []config.CipherID{config.CipherAES256GCM, config.CipherChaCha20Poly1305} {
		t.Run(cid.String(), func(t *testing.T) {
			dir := t.TempDir()

			// Create test file with random content.
			inputPath := filepath.Join(dir, "testfile.bin")
			original := make([]byte, 1024*100+37) // non-aligned size
			rand.Read(original)
			if err := os.WriteFile(inputPath, original, 0o644); err != nil {
				t.Fatal(err)
			}

			password := []byte("test-pass-123")
			encDir := filepath.Join(dir, "enc")
			decDir := filepath.Join(dir, "dec")
			opts := quietOpts(cid)

			// Encrypt.
			encPath, err := fileproc.EncryptFile(inputPath, encDir, password, opts)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			// Verify encrypted file exists and is larger than original.
			encInfo, err := os.Stat(encPath)
			if err != nil {
				t.Fatalf("stat encrypted: %v", err)
			}
			if encInfo.Size() <= int64(len(original)) {
				t.Fatal("encrypted file should be larger than original")
			}

			// Decrypt.
			decPath, err := fileproc.DecryptFile(encPath, decDir, password, opts)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			// Compare.
			decrypted, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(decrypted) != len(original) {
				t.Fatalf("size mismatch: got %d, want %d", len(decrypted), len(original))
			}
			for i := range original {
				if decrypted[i] != original[i] {
					t.Fatalf("byte mismatch at offset %d", i)
				}
			}

			// Verify original filename is preserved.
			if filepath.Base(decPath) != "testfile.bin" {
				t.Fatalf("filename not preserved: got %q", filepath.Base(decPath))
			}
		})
	}
}

// TestWrongPassword verifies that decryption with a wrong password fails
// with an HMAC or auth error, not a silent corruption.
func TestWrongPassword(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "secret.txt")
	os.WriteFile(inputPath, []byte("sensitive data here!"), 0o644)

	encDir := filepath.Join(dir, "enc")
	opts := quietOpts(config.CipherChaCha20Poly1305)

	encPath, err := fileproc.EncryptFile(inputPath, encDir, []byte("correct"), opts)
	if err != nil {
		t.Fatal(err)
	}

	decDir := filepath.Join(dir, "dec")
	_, err = fileproc.DecryptFile(encPath, decDir, []byte("wrong"), opts)
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
}

// TestAnalyze verifies that AnalyzeFile succeeds on a valid encrypted file.
func TestAnalyze(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "analyze_me.dat")
	os.WriteFile(inputPath, []byte("analyze this content"), 0o644)

	encDir := filepath.Join(dir, "enc")
	opts := quietOpts(config.CipherChaCha20Poly1305)

	encPath, err := fileproc.EncryptFile(inputPath, encDir, []byte("pass"), opts)
	if err != nil {
		t.Fatal(err)
	}

	if err := fileproc.AnalyzeFile(encPath, true); err != nil {
		t.Fatalf("analyze: %v", err)
	}
}

// TestTinyFiles verifies that empty and very small files round-trip: the
// format needs no minimum size (3.1.0 refused files under 4 bytes).
func TestTinyFiles(t *testing.T) {
	for n := 0; n < 4; n++ {
		dir := t.TempDir()
		inputPath := filepath.Join(dir, "tiny.txt")
		os.WriteFile(inputPath, []byte("abc")[:n], 0o644)

		opts := quietOpts(config.CipherChaCha20Poly1305)
		encPath, err := fileproc.EncryptFile(inputPath, filepath.Join(dir, "enc"), []byte("pass"), opts)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		decPath, err := fileproc.DecryptFile(encPath, filepath.Join(dir, "dec"), []byte("pass"), opts)
		if err != nil {
			t.Fatalf("%d bytes: decrypt: %v", n, err)
		}
		got, _ := os.ReadFile(decPath)
		if string(got) != "abc"[:n] {
			t.Fatalf("%d bytes: got %q", n, got)
		}
	}
}

// TestUnicodeFilename verifies that Unicode filenames survive the round trip.
func TestUnicodeFilename(t *testing.T) {
	dir := t.TempDir()
	name := "документ_密码_αβγ.txt"
	inputPath := filepath.Join(dir, name)
	os.WriteFile(inputPath, []byte("unicode filename test data"), 0o644)

	encDir := filepath.Join(dir, "enc")
	decDir := filepath.Join(dir, "dec")
	opts := quietOpts(config.CipherChaCha20Poly1305)

	encPath, err := fileproc.EncryptFile(inputPath, encDir, []byte("pass"), opts)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decPath, err := fileproc.DecryptFile(encPath, decDir, []byte("pass"), opts)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if filepath.Base(decPath) != name {
		t.Fatalf("unicode filename not preserved: got %q, want %q", filepath.Base(decPath), name)
	}
}

// TestDryRun verifies that --dry-run does not create output files.
func TestDryRun(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "dryrun.txt")
	os.WriteFile(inputPath, []byte("dry run test"), 0o644)

	encDir := filepath.Join(dir, "enc")
	opts := quietOpts(config.CipherChaCha20Poly1305)
	opts.DryRun = true

	_, err := fileproc.EncryptFile(inputPath, encDir, []byte("pass"), opts)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing may be created, not even the output directory.
	if _, err := os.Stat(encDir); !os.IsNotExist(err) {
		t.Fatalf("dry run created %s (err %v)", encDir, err)
	}
}

// TestProcessFolder verifies batch encryption and decryption of a folder and
// compares every decrypted file with its original.
func TestProcessFolder(t *testing.T) {
	dir := t.TempDir()

	// Create several test files.
	originals := map[string][]byte{}
	for i := 0; i < 5; i++ {
		name := "file_" + string(rune('a'+i)) + ".txt"
		data := make([]byte, 1000+i*500)
		rand.Read(data)
		os.WriteFile(filepath.Join(dir, name), data, 0o644)
		originals[name] = data
	}

	password := []byte("folder-pass")
	opts := quietOpts(config.CipherChaCha20Poly1305)

	// Encrypt folder.
	if err := fileproc.ProcessFolder(dir, password, "encrypt", opts); err != nil {
		t.Fatalf("encrypt folder: %v", err)
	}

	encDir := filepath.Join(dir, "encrypted")
	encEntries, _ := os.ReadDir(encDir)
	if len(encEntries) != 5 {
		t.Fatalf("expected 5 encrypted files, got %d", len(encEntries))
	}

	// Decrypt folder.
	if err := fileproc.ProcessFolder(encDir, password, "decrypt", opts); err != nil {
		t.Fatalf("decrypt folder: %v", err)
	}
	for name, want := range originals {
		got, err := os.ReadFile(filepath.Join(encDir, "decrypted", name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// A wrong password must be reported, not swallowed.
	err := fileproc.ProcessFolder(encDir, []byte("wrong"), "decrypt", opts)
	if !errors.Is(err, fileproc.ErrFolderFailures) {
		t.Fatalf("wrong password in folder mode: %v", err)
	}
}

// TestCorruptedFile verifies that truncation is rejected, both inside the
// header and inside the payload.
func TestCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "corrupt_src.txt")
	os.WriteFile(inputPath, []byte("corruption test data"), 0o644)

	encDir := filepath.Join(dir, "enc")
	opts := quietOpts(config.CipherChaCha20Poly1305)

	encPath, err := fileproc.EncryptFile(inputPath, encDir, []byte("pass"), opts)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(encPath)
	orig, _ := os.ReadFile(encPath)

	for _, size := range []int64{100, int64(config.SystemBlockLen), info.Size() - 1, info.Size() - 5} {
		os.WriteFile(encPath, orig[:size], 0o640)
		if _, err := fileproc.DecryptFile(encPath, filepath.Join(dir, "dec"), []byte("pass"), opts); err == nil {
			t.Fatalf("file truncated to %d bytes was accepted", size)
		}
	}
}
