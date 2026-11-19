package config

import "testing"

// The layout table from README.md ("System Block (810 bytes)"), written out
// independently so that a change in either place is caught.
var readmeLayout = []struct {
	name        string
	offset, len int
	got         int
}{
	{"Signature", 0, 8, SystemBlockOffsets.Signature},
	{"CipherID", 8, 1, SystemBlockOffsets.CipherID},
	{"KDFMode", 9, 1, SystemBlockOffsets.KDFMode},
	{"Salt", 10, 64, SystemBlockOffsets.Salt},
	{"NoncePayload", 74, 24, SystemBlockOffsets.NoncePayload},
	{"NonceFilename", 98, 24, SystemBlockOffsets.NonceFilename},
	{"NonceHash", 122, 24, SystemBlockOffsets.NonceHash},
	{"HMAC", 146, 64, SystemBlockOffsets.HMAC},
	{"FilenameLen", 210, 4, SystemBlockOffsets.FilenameLen},
	{"EncFilename", 214, 512, SystemBlockOffsets.EncFilename},
	{"EncHash", 726, 80, SystemBlockOffsets.EncHash},
	{"OrigNameLen", 806, 4, SystemBlockOffsets.OrigNameLen},
}

func TestSystemBlockMatchesReadme(t *testing.T) {
	end := 0
	for _, f := range readmeLayout {
		if f.got != f.offset {
			t.Errorf("%s: offset %d, README says %d", f.name, f.got, f.offset)
		}
		if f.offset != end {
			t.Errorf("%s: starts at %d, previous field ends at %d (gap or overlap)", f.name, f.offset, end)
		}
		end = f.offset + f.len
	}
	if SystemBlockLen != 810 || end != SystemBlockLen {
		t.Fatalf("SystemBlockLen=%d, fields end at %d, README says 810", SystemBlockLen, end)
	}
	if len(Signature) != SignatureLen || len(OldSignature) != SignatureLen {
		t.Fatalf("signature lengths %d/%d, want %d", len(Signature), len(OldSignature), SignatureLen)
	}
}

func TestDerivedSizes(t *testing.T) {
	const tag = 16 // Poly1305 and GCM tags
	if EncFilenameLen != PaddedFilenameLen+tag {
		t.Errorf("EncFilenameLen=%d, want PaddedFilenameLen+16=%d", EncFilenameLen, PaddedFilenameLen+tag)
	}
	if EncHashLen != 64+tag {
		t.Errorf("EncHashLen=%d, want 80", EncHashLen)
	}
	if ChunkSizeLow <= 0 || ChunkSizeLow > ChunkSize {
		t.Errorf("ChunkSizeLow %d must be in 1..ChunkSize", ChunkSizeLow)
	}
	if MaxFilenameBytes > PaddedFilenameLen {
		t.Errorf("MaxFilenameBytes %d does not fit the %d-byte padded field", MaxFilenameBytes, PaddedFilenameLen)
	}
	if RandomFilenameLen%2 != 0 {
		t.Errorf("RandomFilenameLen %d must be even (hex of whole bytes)", RandomFilenameLen)
	}
	if ChunkSize+tag > 1<<32-1 {
		t.Errorf("a sealed chunk must fit the 32-bit length prefix")
	}
}

func TestCipherID(t *testing.T) {
	cases := []struct {
		id    CipherID
		name  string
		nonce int
	}{
		{CipherAES256GCM, "AES-256-GCM", 12},
		{CipherChaCha20Poly1305, "XChaCha20-Poly1305", 24},
		{0x00, "unknown", 0},
		{0x03, "unknown", 0},
		{0xff, "unknown", 0},
	}
	for _, c := range cases {
		if got := c.id.String(); got != c.name {
			t.Errorf("CipherID(0x%02x).String() = %q, want %q", byte(c.id), got, c.name)
		}
		if got := c.id.NonceSize(); got != c.nonce {
			t.Errorf("CipherID(0x%02x).NonceSize() = %d, want %d", byte(c.id), got, c.nonce)
		}
		if c.nonce > NonceFieldLen {
			t.Errorf("nonce %d does not fit the %d-byte field", c.nonce, NonceFieldLen)
		}
	}
}

func TestArgon2Parameters(t *testing.T) {
	if Argon2Memory != 4<<20 || Argon2MemoryLow != 64<<10 {
		t.Errorf("memory costs %d/%d KiB, README says 4 GiB / 64 MiB", Argon2Memory, Argon2MemoryLow)
	}
	if Argon2Time != 8 || Argon2Threads != 8 || Argon2KeyLen != 32 {
		t.Errorf("t=%d p=%d keylen=%d, README says 8/8/32", Argon2Time, Argon2Threads, Argon2KeyLen)
	}
}

func TestKDFMode(t *testing.T) {
	cases := []struct {
		m     KDFMode
		valid bool
		mem   uint32
	}{
		{KDFUnrecorded, true, Argon2Memory},
		{KDFLowMemory, true, Argon2MemoryLow},
		{KDFStandard, true, Argon2Memory},
		{0x03, false, Argon2Memory},
		{0xff, false, Argon2Memory},
	}
	for _, c := range cases {
		if c.m.Valid() != c.valid || c.m.MemoryKiB() != c.mem {
			t.Errorf("KDFMode(0x%02x): valid=%v mem=%d", byte(c.m), c.m.Valid(), c.m.MemoryKiB())
		}
		if (c.m.String() == "unknown") == c.valid {
			t.Errorf("KDFMode(0x%02x).String() = %q", byte(c.m), c.m.String())
		}
	}
	// 3.1.0 always wrote 0x00 here, and the threshold must leave room for 4 GiB.
	if KDFUnrecorded != 0 || Argon2MemoryThreshold < Argon2Memory*1024+Argon2MemoryHeadroom {
		t.Fatal("KDF constants are inconsistent")
	}
}
