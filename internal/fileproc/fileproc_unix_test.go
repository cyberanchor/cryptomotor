//go:build unix

package fileproc

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"cryptomotor/internal/config"
)

// A named pipe is never opened: opening it blocks until a writer appears.
// 3.1.0 hung forever in --decrypt --folder on a FIFO.
func TestFolderSkipsNamedPipe(t *testing.T) {
	for _, mode := range []string{"encrypt", "decrypt"} {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "pipe")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skip("mkfifo:", err)
		}
		mustWrite(t, filepath.Join(dir, "a.txt"), []byte("regular file"))
		done := make(chan error, 1)
		go func() { done <- ProcessFolder(dir, []byte("pw"), mode, lowOpts(config.CipherChaCha20Poly1305)) }()
		select {
		case err := <-done:
			if mode == "encrypt" && err != nil {
				t.Errorf("%s: %v", mode, err)
			}
		case <-time.After(20 * time.Second):
			// Unblock the open so that the test can finish, then fail.
			if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
				w.Close()
			}
			<-done
			t.Errorf("%s: ProcessFolder blocked on a named pipe", mode)
		}
	}
}

func TestEncryptRefusesSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	if _, err := EncryptFile(fifo, filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("FIFO: %v", err)
	}
	if _, err := EncryptFile("/dev/null", filepath.Join(dir, "enc"), []byte("pw"), lowOpts(config.CipherChaCha20Poly1305)); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("/dev/null: %v", err)
	}
}

// A dangling symlink at the output name counts as an existing file.
func TestPublishKeepsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	tmp := mustWrite(t, filepath.Join(dir, "x.tmp"), []byte("new"))
	link := filepath.Join(dir, "final")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Skip(err)
	}
	if err := publish(tmp, link, false); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !os.IsNotExist(err) {
		t.Fatal("followed the symlink")
	}
}
