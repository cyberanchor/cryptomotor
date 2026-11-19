package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateFlags(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	os.WriteFile(file, []byte("data"), 0o600)
	missing := filepath.Join(dir, "missing")

	type args struct {
		enc, dec, ana      bool
		folder, file, p, f string
	}
	cases := []struct {
		name string
		a    args
		want string // "" = valid
	}{
		{"no mode", args{}, "specify one of"},
		{"two modes", args{enc: true, dec: true, file: file}, "only one of"},
		{"three modes", args{enc: true, dec: true, ana: true, file: file}, "only one of"},
		{"analyze without file", args{ana: true, folder: dir}, "--analyze requires --file"},
		{"encrypt without target", args{enc: true}, "requires --folder or --file"},
		{"decrypt without target", args{dec: true}, "requires --folder or --file"},
		{"folder and file", args{enc: true, folder: dir, file: file}, "not both"},
		{"password and file", args{enc: true, file: file, p: "x", f: file}, "not both"},
		{"missing folder", args{enc: true, folder: missing}, `folder "`},
		{"folder is a file", args{enc: true, folder: file}, "is not a directory"},
		{"missing file", args{dec: true, file: missing}, `file "`},
		{"file is a dir", args{dec: true, file: dir}, "use --folder instead"},
		{"valid encrypt file", args{enc: true, file: file}, ""},
		{"valid decrypt folder", args{dec: true, folder: dir, p: "x"}, ""},
		{"valid analyze", args{ana: true, file: file}, ""},
		{"analyze ignores password", args{ana: true, file: file, p: "x"}, ""},
	}
	for _, c := range cases {
		err := validateFlags(c.a.enc, c.a.dec, c.a.ana, c.a.folder, c.a.file, c.a.p, c.a.f, nil)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		case strings.HasPrefix(c.name, "missing") && !errors.Is(err, fs.ErrNotExist):
			t.Errorf("%s: err = %v, want fs.ErrNotExist", c.name, err)
		}
	}
	// CM-27: a stray positional argument is an error, not silently ignored.
	if err := validateFlags(true, false, false, "", file, "x", "", []string{"stray"}); err == nil || !strings.Contains(err.Error(), `unexpected argument "stray"`) {
		t.Errorf("stray argument: %v", err)
	}
}

func TestResolvePassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	if got, src, err := resolvePassword("flag pw", ""); err != nil || string(got) != "flag pw" || src != "--password" {
		t.Errorf("flag: %q %q %v", got, src, err)
	}
	// CM-12: only a leading UTF-8 BOM and trailing line breaks are removed.
	cases := map[string]string{
		"secret\n":                       "secret",
		"secret\r\n":                     "secret",
		"secret":                         "secret",
		"secret\n\n":                     "secret",
		"\xef\xbb\xbfsecret\r\n":         "secret",
		"  two leading, one trailing \n": "  two leading, one trailing ",
		"\tpw\n":                         "\tpw",
		"пароль-密码\n":                    "пароль-密码",
		"line1\nline2\n":                 "line1\nline2",
		"\n":                             "",
	}
	i := 0
	for content, want := range cases {
		i++
		got, src, err := resolvePassword("", write(fmt.Sprint("pw", i), content))
		if err != nil || string(got) != want || src != "--password-file" {
			t.Errorf("file %q: got %q (%s, %v), want %q", content, got, src, err, want)
		}
	}
	if _, _, err := resolvePassword("", filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "read password file") {
		t.Errorf("missing file: %v", err)
	}
	if _, _, err := resolvePassword("", dir); err == nil {
		t.Error("directory as password file accepted")
	}
	// No flag, no file and stdin is not a terminal: the prompt must fail, not hang.
	r, w, _ := os.Pipe()
	w.Write([]byte("piped\n"))
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	if _, _, err := resolvePassword("", ""); err == nil || !strings.Contains(err.Error(), "stdin is not a terminal") {
		t.Errorf("non-terminal stdin: %v", err)
	}
}
