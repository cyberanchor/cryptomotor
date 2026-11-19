<div align="center">

```
 _____             _       _____     _           
|     |___ _ _ ___| |_ ___|     |___| |_ ___ ___ 
|   --|  _| | | . |  _| . | | | | . |  _| . |  _|
|_____|_| |_  |  _|_| |___|_|_|_|___|_| |___|_|  
          |___|_|                                 
```

**Just For Fun! cross-platform command-line tool for file encryption and decryption.**<br>
*Utilizing XChaCha20-Poly1305, AES-256-GCM, HMAC-SHA512, and Argon2id.*

<br>

![Version](https://img.shields.io/badge/version-3.2.0-blue?style=flat-square)
![Go](https://img.shields.io/badge/Go-1.27.4+-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey?style=flat-square)
![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-orange?style=flat-square)
![Cipher](https://img.shields.io/badge/cipher-XChaCha20--Poly1305-blueviolet?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-Argon2id%204%20GiB-red?style=flat-square)

<br>

[installation](#installation) •
[usage](#usage) •
[cryptographic architecture](#cryptographic-architecture) •
[all flags](#all-flags) •
[changelog](CHANGELOG.md) •
[releases](https://github.com/cyberanchor/cryptomotor/releases)

</div>

-----

## Cryptographic architecture

```text
Password
    │
    ▼
┌─────────────────────────────────────────────┐
│  Argon2id (4 GiB / 8 iter / 8 threads)      │
│  or 64 MiB with --low-memory                │
│  salt: 64 random bytes                      │
└──────────────┬──────────────────────────────┘
               │ 256-bit key
               ▼
    ┌──────────┴──────────┐
    │    AEAD Cipher       │
    │  XChaCha20-Poly1305  │
    │    or AES-256-GCM    │
    └──┬──────┬──────┬────┘
       │      │      │
  nonce₁  nonce₂  nonce₃     ← three independent random nonces
       │      │      │
   payload  filename  hash
       │      │      │
       ▼      ▼      ▼
  ┌────────────────────────┐
  │  HMAC-SHA512           │
  │  (Encrypt-then-MAC)    │
  │  signs: salt +         │
  │    ciphertext stream + │
  │    enc_filename +      │
  │    enc_hash            │
  └────────────────────────┘
```

### Key derivation cost

The default Argon2id cost is 4 GiB of memory, 8 passes and 8 lanes. With
`--low-memory`, or automatically when less than 8 GiB of RAM is free, files are
encrypted with 64 MiB instead and a warning is printed. The cost used is
recorded in the file (offset 9), so decryption never needs a flag. A file that
records the 4 GiB cost is refused up front on a machine with less than about
4.5 GiB of free RAM, instead of swapping or being killed.

Files written by 3.1.0 and earlier do not record the cost: they are tried with
64 MiB first and then with 4 GiB; `--low-memory` limits the attempt to 64 MiB.

### Streaming encryption

Large files are never loaded entirely into memory. The payload is split into
chunks (64 MiB, or 512 KiB with the 64 MiB cost), each sealed in place with a
unique nonce derived from `base_nonce ⊕ counter`. Each chunk is prefixed with a
4-byte big-endian length, and the stream ends with a zero-length record. A
decoder accepts chunks of any size up to 64 MiB plus the tag, requires the end
record and rejects anything after it. Peak memory is about the Argon2id cost
plus one chunk: about 70 MiB with the 64 MiB cost.

### System Block (810 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 8 | Signature (`CMv3\x00\x00\x00\x00`) |
| 8 | 1 | Cipher ID (`0x01` = AES-GCM, `0x02` = XChaCha) |
| 9 | 1 | Argon2id cost (`0x01` = 64 MiB, `0x02` = 4 GiB, `0x00` = not recorded: 3.1.0 and earlier) |
| 10 | 64 | Salt |
| 74 | 24 | Nonce (payload) |
| 98 | 24 | Nonce (filename) |
| 122 | 24 | Nonce (hash) |
| 146 | 64 | HMAC-SHA512 |
| 210 | 4 | Padded filename length (always 496) |
| 214 | 512 | Encrypted filename (496 bytes, zero-padded, + 16-byte tag) |
| 726 | 80 | Encrypted SHA-512 of the plaintext (+ 16-byte tag) |
| 806 | 4 | Original filename length in bytes |

For AES-256-GCM the 12-byte nonces are right-aligned and the first 12 bytes of
each nonce field are zero. HMAC does not cover the header itself, so every
header field is checked on decryption: fixed values (signature, padded length,
nonce padding) must match, the cipher and cost bytes must be known (and a wrong
one cannot produce a valid key or tag), and the filename length must agree with
the decrypted name. The filename length is still stored in clear text, because
3.1.0 needs it; `--analyze` does not print it.

### File names

The original file name is stored encrypted and restored on decryption. It is
used only if it is a plain file name on the decrypting system: names such as
`../../.bashrc`, `..`, `/etc/passwd`, `a/b` (and on Windows `a\b`, `C:x`,
`CON`) are refused. An existing file is never replaced unless `--force` is
given; a directory is never replaced. Control characters in names are shown
escaped in messages.

## Installation

### From a release

Download the archive for your platform and `sha256sums.txt` from the
[releases](https://github.com/cyberanchor/cryptomotor/releases) page:

```bash
sha256sum --ignore-missing -c sha256sums.txt
gh attestation verify cryptomotor_v3.2.0_linux_amd64.zip --repo cyberanchor/cryptomotor
unzip cryptomotor_v3.2.0_linux_amd64.zip cryptomotor
./cryptomotor --help
```

Archives for linux/amd64, linux/arm64 and windows/amd64 contain the binary,
README.md, LICENSE and CHANGELOG.md.

### From source

Requires Go 1.27.4 or newer; packaging also needs `zip`.

```bash
git clone https://github.com/cyberanchor/cryptomotor
cd cryptomotor
go build -trimpath -o cryptomotor ./cmd/cryptomotor    # just the binary
make build                                             # binary + docs zipped in output/
```

### Make targets

| Target | Description |
|--------|-------------|
| `make build` | Build and package for the current OS/arch into `output/` |
| `make all` | Release archives for linux/amd64, linux/arm64, windows/amd64 and `output/sha256sums.txt` |
| `make verify-reproducible` | Build the release twice (the second time with an empty build cache) and compare |
| `make test` / `make test-short` | All tests; `-short` skips the 192 MiB streaming test |
| `make race` | Tests under the race detector |
| `make e2e [OLD=cryptomotor-3.1.0]` | End-to-end tests of the real binary on real files |
| `make check` | gofmt, `go vet` for Linux and Windows, `go mod verify` |
| `make vulncheck` | govulncheck |
| `make bench` | Crypto benchmarks |
| `make clean` | Remove `output/` |

Release binaries are static (`CGO_ENABLED=0`), stripped (`-s -w`) and built
with `-trimpath -buildvcs=false -buildid=`; archives use fixed timestamps and
modes. Building a tag with the same Go version gives byte-identical archives.

## Usage

### Encrypt a single file

```bash
cryptomotor --encrypt --file ./secret.pdf --password-file ./key.txt
# Output: ./encrypted/a1b2c3d4…  (random name; the original name is stored encrypted)
```

### Decrypt a single file

```bash
cryptomotor --decrypt --file ./encrypted/a1b2c3d4 --password-file ./key.txt
# Output: ./encrypted/decrypted/secret.pdf  (a "decrypted" folder next to the encrypted file)
```

### Encrypt or decrypt all files in a folder

```bash
cryptomotor --encrypt --folder ./documents --password-file ./key.txt --verbose
cryptomotor --decrypt --folder ./documents/encrypted --password-file ./key.txt
```

Folder mode handles the regular files directly inside the folder; subfolders,
named pipes and devices are skipped. The exit status is 1 if any file failed.

### Analyze an encrypted file (no password needed)

```bash
cryptomotor --analyze --file ./encrypted/a1b2c3d4 --debug
```

### Other options

```bash
cryptomotor --encrypt --file ./data.bin --aes            # AES-256-GCM instead of XChaCha20-Poly1305
cryptomotor --encrypt --file ./data.bin --low-memory     # Argon2id with 64 MiB
cryptomotor --decrypt --file ./encrypted/x --force       # replace an existing output file
```

Without `--password` or `--password-file` the password is read from the
terminal without echo. A password file loses a leading UTF-8 BOM and trailing
line breaks; spaces and tabs are part of the password.

## All Flags

| Flag | Description |
|------|-------------|
| `--encrypt` | Encrypt files |
| `--decrypt` | Decrypt files |
| `--analyze` | Inspect the system block of an encrypted file (no password) |
| `--folder <path>` | Process every regular file directly inside a folder |
| `--file <path>` | Process a single file |
| `--password <str>` | Password (visible in the process list and shell history: prefer `--password-file` or the prompt) |
| `--password-file <path>` | Read the password from a UTF-8 file |
| `--aes` | Encrypt with AES-256-GCM instead of XChaCha20-Poly1305 |
| `--low-memory` | Encrypt with the 64 MiB Argon2id cost (recorded in the file) |
| `--force` | Replace existing output files when decrypting |
| `--dry-run` | Show what would happen; writes no files and creates no folders (decryption still checks the password) |
| `--no-progress` | Disable progress bars (shown only when stderr is a terminal) |
| `--verbose` | Informational messages |
| `--debug` | Header fields, nonces, sizes and timings; no keys or passwords |
| `--trace` | Everything `--debug` shows plus the **password, derived keys, plaintext hashes, original names and every chunk**. ⚠️ For troubleshooting only: do not use on shared systems, delete the output afterwards |
| `--log <path>` | Also write every message and the enabled debug/trace records to this file (mode 0600, appended) |

Colours are used only when stderr is a terminal and `NO_COLOR` is not set.

### Exit status

| Status | Meaning |
|--------|---------|
| 0 | Success |
| 1 | Error; in folder mode, at least one file failed |
| 2 | Unknown flag |
| 130 / 143 | Interrupted by SIGINT (Ctrl+C) / SIGTERM; partial output files are removed |

## Compatibility

| | Decrypted by 3.1.0 | Decrypted by 3.2.0 |
|---|---|---|
| File from 3.1.0 | yes, with the same `--low-memory` setting | yes, no flag needed |
| File from 3.2.0 | yes; add `--low-memory` if it used 64 MiB (`--analyze` shows it) | yes, no flag needed |

## Development

```bash
make check test race       # format, vet, unit tests
make e2e                   # end-to-end tests (Linux), see e2e/e2e.sh
make vulncheck
```

CI runs the tests on Linux amd64, Linux arm64 and Windows, the race detector,
govulncheck, the end-to-end tests (including the 4 GiB setting and
compatibility with the 3.1.0 release) and the reproducible-build check. Pushing
a tag `vX.Y.Z` that matches `ProgramVersion` runs the release workflow, which
publishes the archives, `sha256sums.txt`, the CHANGELOG section and signed
build provenance.

## Disclaimer

`cryptomotor` is intended exclusively for personal, lawful use. The author
is not responsible for any misuse of this software.

## License

[MIT](LICENSE)
