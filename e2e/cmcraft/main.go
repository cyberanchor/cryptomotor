// cmcraft is an independent implementation of the cryptomotor v3 file format,
// written from the README specification and used by e2e/e2e.sh. It does not
// import any cryptomotor package, so it checks that the specification and the
// implementation agree, and it can build hostile files that cryptomotor itself
// would never write.
//
//	cmcraft decrypt  -in FILE -password PW [-out FILE]
//	    Parse the header, derive the key (Argon2id 64 MiB, the --low-memory mode),
//	    verify HMAC, decrypt name/hash/payload, verify SHA-512. Prints name, size, sha256.
//	cmcraft craft    -in PLAINTEXT -out FILE -password PW [-name NAME] [-aes]
//	                 [-orignamelen N] [-chunklen N] [-nosentinel]
//	    Write a file with a correct HMAC and AEAD tags but attacker-chosen fields:
//	      -name          any stored filename, e.g. "../../x" (no filepath.Base)
//	      -orignamelen   value stored in the cleartext OrigNameLen field
//	      -chunklen      declared length of the first chunk (body = real ciphertext)
//	      -nosentinel    omit the zero-length EOF record
//	      -badhash       store the SHA-512 of different data (HMAC still valid)
//
// Only the 64 MiB Argon2id cost is supported (KDF mode byte 0x00 or 0x01);
// crafted files record mode 0x01.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Layout from README.md "System Block (810 bytes)".
const (
	offSig, lenSig         = 0, 8
	offCipher              = 8
	offKDF                 = 9
	offSalt, lenSalt       = 10, 64
	offNonceP              = 74
	offNonceF              = 98
	offNonceH              = 122
	lenNonceField          = 24
	offHMAC, lenHMAC       = 146, 64
	offEncNameLen          = 210
	offEncName, lenEncName = 214, 512
	offEncHash, lenEncHash = 726, 80
	offOrigNameLen         = 806
	headerLen              = 810
	paddedName             = 496
	chunkSize              = 64 << 20
	signature              = "CMv3\x00\x00\x00\x00"
)

func deriveKey(pw, salt []byte) []byte {
	return argon2.IDKey(pw, salt, 8, 64*1024, 8, 32)
}

func newAEAD(key []byte, id byte) (cipher.AEAD, error) {
	switch id {
	case 0x01:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	case 0x02:
		return chacha20poly1305.NewX(key)
	}
	return nil, fmt.Errorf("unknown cipher 0x%02x", id)
}

func chunkNonce(base []byte, ctr uint64) []byte {
	n := append([]byte(nil), base...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], ctr)
	for i := 0; i < 8; i++ {
		n[len(n)-8+i] ^= c[i]
	}
	return n
}

func nonceFromField(field []byte, size int) []byte { return field[lenNonceField-size:] }

func decrypt(in, outPath string, pw []byte) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	if len(data) < headerLen {
		return errors.New("short file")
	}
	h := data[:headerLen]
	if string(h[offSig:offSig+lenSig]) != signature {
		return errors.New("bad signature")
	}
	if h[offKDF] > 0x01 {
		return fmt.Errorf("KDF mode 0x%02x: cmcraft only derives the 64 MiB setting", h[offKDF])
	}
	salt := h[offSalt : offSalt+lenSalt]
	key := deriveKey(pw, salt)
	aead, err := newAEAD(key, h[offCipher])
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	encName := h[offEncName : offEncName+lenEncName]
	encHash := h[offEncHash : offEncHash+lenEncHash]

	// HMAC-SHA512(key, salt || everything after the header || encName || encHash)
	mac := hmac.New(sha512.New, key)
	mac.Write(salt)
	mac.Write(data[headerLen:])
	mac.Write(encName)
	mac.Write(encHash)
	if !hmac.Equal(mac.Sum(nil), h[offHMAC:offHMAC+lenHMAC]) {
		return errors.New("HMAC mismatch")
	}
	name, err := aead.Open(nil, nonceFromField(h[offNonceF:offNonceF+lenNonceField], ns), encName, nil)
	if err != nil {
		return fmt.Errorf("filename: %w", err)
	}
	wantHash, err := aead.Open(nil, nonceFromField(h[offNonceH:offNonceH+lenNonceField], ns), encHash, nil)
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	origLen := binary.BigEndian.Uint32(h[offOrigNameLen:])
	base := nonceFromField(h[offNonceP:offNonceP+lenNonceField], ns)

	var plain bytes.Buffer
	rest := data[headerLen:]
	sentinel := false
	for ctr := uint64(0); len(rest) >= 4; ctr++ {
		l := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if l == 0 {
			sentinel = true
			break
		}
		if uint64(l) > uint64(len(rest)) || l > chunkSize+uint32(aead.Overhead()) {
			return fmt.Errorf("chunk %d: bad length %d", ctr, l)
		}
		pt, err := aead.Open(nil, chunkNonce(base, ctr), rest[:l], nil)
		if err != nil {
			return fmt.Errorf("chunk %d: %w", ctr, err)
		}
		plain.Write(pt)
		rest = rest[l:]
	}
	if !sentinel || len(rest) != 0 {
		return fmt.Errorf("stream framing: sentinel=%v trailing=%d", sentinel, len(rest))
	}
	got := sha512.Sum512(plain.Bytes())
	if !bytes.Equal(got[:], wantHash) {
		return errors.New("SHA-512 mismatch")
	}
	sum := sha256.Sum256(plain.Bytes())
	fmt.Printf("ok cipher=0x%02x kdf=0x%02x encnamelen=%d orignamelen=%d name=%q size=%d sha256=%s\n",
		h[offCipher], h[offKDF], binary.BigEndian.Uint32(h[offEncNameLen:]), origLen,
		string(bytes.TrimRight(name, "\x00")), plain.Len(), hex.EncodeToString(sum[:]))
	if outPath != "" {
		return os.WriteFile(outPath, plain.Bytes(), 0o600)
	}
	return nil
}

func craft(in, out string, pw []byte, name string, useAES bool, origLen int64, chunkLen int64, noSentinel, badHash bool) error {
	plain, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	if len(name) > paddedName {
		return errors.New("name longer than 496 bytes")
	}
	salt := make([]byte, lenSalt)
	rand.Read(salt)
	key := deriveKey(pw, salt)
	id := byte(0x02)
	if useAES {
		id = 0x01
	}
	aead, err := newAEAD(key, id)
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	nonce := func() []byte { n := make([]byte, ns); rand.Read(n); return n }
	baseP, nF, nH := nonce(), nonce(), nonce()

	// Payload stream: [len][ct] per 64 MiB chunk, then a zero record.
	var stream bytes.Buffer
	for ctr, off := uint64(0), 0; off < len(plain); ctr++ {
		end := off + chunkSize
		if end > len(plain) {
			end = len(plain)
		}
		ct := aead.Seal(nil, chunkNonce(baseP, ctr), plain[off:end], nil)
		l := uint32(len(ct))
		if ctr == 0 && chunkLen >= 0 {
			l = uint32(chunkLen)
		}
		binary.Write(&stream, binary.BigEndian, l)
		stream.Write(ct)
		off = end
	}
	if !noSentinel {
		stream.Write([]byte{0, 0, 0, 0})
	}

	padded := make([]byte, paddedName)
	copy(padded, name)
	encName := aead.Seal(nil, nF, padded, nil)
	sum := sha512.Sum512(plain)
	if badHash {
		sum = sha512.Sum512(append(plain, 'x'))
	}
	encHash := aead.Seal(nil, nH, sum[:], nil)

	mac := hmac.New(sha512.New, key)
	mac.Write(salt)
	mac.Write(stream.Bytes())
	mac.Write(encName)
	mac.Write(encHash)

	h := make([]byte, headerLen)
	copy(h[offSig:], signature)
	h[offCipher] = id
	h[offKDF] = 0x01 // Argon2id 64 MiB
	copy(h[offSalt:], salt)
	copy(h[offNonceP+lenNonceField-ns:], baseP)
	copy(h[offNonceF+lenNonceField-ns:], nF)
	copy(h[offNonceH+lenNonceField-ns:], nH)
	copy(h[offHMAC:], mac.Sum(nil))
	binary.BigEndian.PutUint32(h[offEncNameLen:], paddedName)
	copy(h[offEncName:], encName)
	copy(h[offEncHash:], encHash)
	if origLen < 0 {
		origLen = int64(len(name))
	}
	binary.BigEndian.PutUint32(h[offOrigNameLen:], uint32(origLen))

	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(h); err != nil {
		return err
	}
	_, err = io.Copy(f, &stream)
	return err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cmcraft decrypt|craft [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	in := fs.String("in", "", "input file")
	out := fs.String("out", "", "output file")
	pw := fs.String("password", "", "password")
	name := fs.String("name", "", "stored filename (craft)")
	useAES := fs.Bool("aes", false, "AES-256-GCM (craft)")
	origLen := fs.Int64("orignamelen", -1, "cleartext OrigNameLen value (craft)")
	chunkLen := fs.Int64("chunklen", -1, "declared length of chunk 0 (craft)")
	noSentinel := fs.Bool("nosentinel", false, "omit EOF record (craft)")
	badHash := fs.Bool("badhash", false, "store the SHA-512 of different data (craft)")
	fs.Parse(os.Args[2:])

	var err error
	switch os.Args[1] {
	case "decrypt":
		err = decrypt(*in, *out, []byte(*pw))
	case "craft":
		err = craft(*in, *out, []byte(*pw), *name, *useAES, *origLen, *chunkLen, *noSentinel, *badHash)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmcraft:", err)
		os.Exit(1)
	}
}
