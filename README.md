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

![Version](https://img.shields.io/badge/version-3.1.0-blue?style=flat-square)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey?style=flat-square)
![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-orange?style=flat-square)
![Cipher](https://img.shields.io/badge/cipher-XChaCha20--Poly1305-blueviolet?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-Argon2id%204%20GiB-red?style=flat-square)

<br>

[Installation](#installation) •
[Usage](#usage) •
[Cryptographic Architecture](#cryptographic-architecture) •
[All Flags](#all-flags)

</div>

-----

## Cryptographic Architecture

```text
Password
    │
    ▼
┌─────────────────────────────────────────────┐
│  Argon2id (4 GiB / 8 iter / 8 threads)     │
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
  │  signs: ciphertext +   │
  │    enc_filename +      │
  │    enc_hash            │
  └────────────────────────┘
```

### Streaming Encryption

Large files are never loaded entirely into memory. The payload is split into
64 MiB chunks, each encrypted with a unique nonce derived from `base_nonce ⊕ counter`.
Each chunk is prefixed with a 4-byte big-endian length, and the stream ends
with a zero-length sentinel.

### System Block (810 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 8 | Signature (`CMv3\x00\x00\x00\x00`) |
| 8 | 1 | Cipher ID (`0x01` = AES-GCM, `0x02` = XChaCha) |
| 9 | 1 | Reserved |
| 10 | 64 | Salt |
| 74 | 24 | Nonce (payload) |
| 98 | 24 | Nonce (filename) |
| 122 | 24 | Nonce (hash) |
| 146 | 64 | HMAC-SHA512 |
| 210 | 4 | Encrypted filename length |
| 214 | 512 | Encrypted filename |
| 726 | 80 | Encrypted SHA-512 hash |
| 806 | 4 | Original filename length |

## Installation

### From source (current platform)

```bash
cd cryptomotor
make build
# ZIP archive with binary + README appears in output/
```

### Cross-compile for release

```bash
make all
# Release .zip archives and sha256sums.txt appear in output/
# Targets: linux/amd64, linux/arm64, windows/amd64
```

### Make targets

| Target | Description |
|--------|-------------|
| `make build` | Build and package for current OS/arch |
| `make all` | Cross-compile and package for all release targets |
| `make test` | Run all tests with race detector |
| `make bench` | Run crypto benchmarks |
| `make clean` | Remove build artifacts |
| `make lint` | Static analysis (requires golangci-lint) |

## Usage

### Encrypt a single file

```bash
cryptomotor --encrypt --file ./secret.pdf --password mypass
# Output: ./encrypted/a1b2c3d4...
```

### Decrypt a single file

```bash
cryptomotor --decrypt --file ./encrypted/a1b2c3d4 --password-file ./key.txt
# Output: ./decrypted/secret.pdf
```

### Encrypt all files in a folder

```bash
cryptomotor --encrypt --folder ./documents --password mypass --verbose
```

### Decrypt all files in a folder

```bash
cryptomotor --decrypt --folder ./documents/encrypted --password mypass
```

### Analyze an encrypted file

```bash
cryptomotor --analyze --file ./encrypted/a1b2c3d4 --debug
```

### Use AES-256-GCM instead of XChaCha20

```bash
cryptomotor --encrypt --file ./data.bin --password mypass --aes
```

### Low-memory mode (64 MiB Argon2id)

```bash
cryptomotor --encrypt --file ./data.bin --password mypass --low-memory
```

## All Flags

| Flag | Description |
|------|-------------|
| `--encrypt` | Encrypt files |
| `--decrypt` | Decrypt files |
| `--analyze` | Inspect system block of an encrypted file |
| `--folder <path>` | Process all files in a directory |
| `--file <path>` | Process a single file |
| `--password <str>` | Password (prefer `--password-file` or interactive prompt) |
| `--password-file <path>` | Read password from a UTF-8 file |
| `--aes` | Use AES-256-GCM instead of XChaCha20-Poly1305 |
| `--low-memory` | Reduce Argon2id memory to 64 MiB |
| `--verbose` | Print informational messages |
| `--debug` | Full debug output: system block hex dumps, keys, salts, nonces, HMAC values. **⚠️ Exposes secrets in logs — do NOT use in production** |
| `--dry-run` | Simulate without writing output |
| `--no-progress` | Disable progress bars |
| `--log <path>` | Write structured logs to file |


## Disclaimer

cryptomotor is intended exclusively for personal, lawful use. The author
is not responsible for any misuse of this software.
