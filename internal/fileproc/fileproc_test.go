package fileproc_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"cryptomotor/internal/config"
	"cryptomotor/internal/fileproc"
	"cryptomotor/internal/logger"
)

func init() {
	// Suppress log output during tests.
	logger.Init("", false, false)
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

// TestFileTooSmall verifies that files below MinFileSize are rejected.
func TestFileTooSmall(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "tiny.txt")
	os.WriteFile(inputPath, []byte("ab"), 0o644) // 2 bytes < MinFileSize=4

	opts := quietOpts(config.CipherChaCha20Poly1305)
	_, err := fileproc.EncryptFile(inputPath, filepath.Join(dir, "enc"), []byte("pass"), opts)
	if err == nil {
		t.Fatal("expected error for file too small")
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

	// The encrypted directory should not exist (or be empty).
	entries, _ := os.ReadDir(encDir)
	if len(entries) > 0 {
		t.Fatal("dry run should not create output files")
	}
}

// TestProcessFolder verifies batch encryption and decryption of a folder.
func TestProcessFolder(t *testing.T) {
	dir := t.TempDir()

	// Create several test files.
	for i := 0; i < 5; i++ {
		name := filepath.Join(dir, "file_"+string(rune('a'+i))+".txt")
		data := make([]byte, 1000+i*500)
		rand.Read(data)
		os.WriteFile(name, data, 0o644)
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
}

// TestCorruptedFile verifies that a truncated file is rejected.
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

	// Truncate the encrypted file.
	os.Truncate(encPath, 100)

	_, err = fileproc.DecryptFile(encPath, filepath.Join(dir, "dec"), []byte("pass"), opts)
	if err == nil {
		t.Fatal("expected error for corrupted file")
	}
}
