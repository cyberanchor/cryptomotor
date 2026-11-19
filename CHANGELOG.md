# Changelog

All notable changes to cryptomotor. The file format stays v3: files from 3.1.0
decrypt with this version, and 3.1.0 decrypts files from this version (give it
`--low-memory` when the file used the 64 MiB setting).

## [3.2.0] - 2026-11-19

Fixes from the audit of 2026-11-19 (finding IDs CM-xx in parentheses).

### Security

- A file name stored in an encrypted file is used only if it is a plain file
  name: `../../.bashrc`, `..`, absolute paths, names with `/` (and on Windows
  `\`, drive letters, `CON`, `NUL`…) are refused. Before, decrypting a crafted
  file could write anywhere and replace files such as `~/.bashrc` (CM-01).
- Decryption never replaces an existing file; `--force` allows it. Two files
  with the same name in one folder no longer overwrite each other silently
  (CM-02).
- Header fields that HMAC does not cover are checked: the name length (a bad
  value used to panic or rename the output), the padded-length field, the
  unused AES nonce bytes, the cipher and KDF bytes (CM-03, CM-23).
- A chunk longer than 64 MiB plus the tag is rejected before memory is
  allocated for it; a crafted length used to allocate 4 GiB (CM-07). The
  end-of-stream record is now required and nothing may follow it (CM-24).
- Names and messages are printed with control characters escaped, so a name
  cannot send terminal escape sequences (CM-10).
- Decrypted files are created with mode 0600, log files with 0600.

### Fixed

- The Argon2id cost is recorded in the file (the formerly reserved byte at
  offset 9), so decryption no longer needs `--low-memory`. Files from 3.1.0
  and earlier are tried with 64 MiB first, then 4 GiB (CM-04).
- Encryption falls back to the 64 MiB cost when less than 8 GiB of RAM is free,
  as the code always intended; a 4 GiB derivation that does not fit in RAM is
  refused with a clear message instead of swapping or crashing (CM-04).
- `--folder` exits with status 1 when any file failed (CM-06). Unreadable files
  count as failed, not as "not a cryptomotor file" (CM-15).
- `--decrypt --folder` no longer hangs forever on a named pipe; special files
  are skipped in both modes (CM-28).
- Ctrl+C or SIGTERM removes partial output files and temporary files with
  decrypted data (exit status 130/143) (CM-08), and restores the terminal echo
  when it arrives at the password prompt (CM-11).
- `--password-file` removes only a UTF-8 BOM and trailing line breaks; spaces
  and tabs are part of the password, as with `--password` (CM-12).
- `--log` records every message, not only debug records (CM-13).
- `--dry-run` creates no directories and skips the key derivation when
  encrypting (CM-14).
- The binary reports the right version (CM-16); the error for an unknown cipher
  names the byte (CM-17).
- `--low-memory` now really is low: 512 KiB chunks sealed in place, about
  70 MiB peak instead of about 200 MiB (CM-18).
- Windows: partial files are closed before they are removed; names up to the
  496-byte field are accepted (CM-19).
- Empty files and files under 4 bytes can be encrypted (CM-27).
- A stray command-line argument is an error instead of being ignored (CM-27).
- Progress bars and colours appear only on a terminal; `NO_COLOR` is honoured;
  the decrypt banner no longer claims a cipher (CM-27).

### Added

- `--trace`: everything `--debug` shows plus the password, derived keys,
  plaintext hashes, original names and every chunk. Sensitive by design.
- `--force`: replace existing output files when decrypting.
- `--debug` no longer prints keys or passwords.
- LICENSE (MIT), this changelog, CI (vet, tests on Linux amd64/arm64 and
  Windows, race detector, govulncheck, end-to-end tests, reproducible build
  check) and a release workflow with SHA-256 sums and build provenance.
- End-to-end tests (`e2e/`) and an independent implementation of the format
  used by them (`e2e/cmcraft`).

### Changed

- Go 1.27.4; golang.org/x/crypto v0.59.0, x/term v0.48.0, x/sys v0.50.0.
- Release archives also contain LICENSE and CHANGELOG.md and are byte-for-byte
  reproducible (`make all`, `make verify-reproducible`).

### Compatibility notes

- A password file whose password really starts or ends with spaces or tabs was
  read without them by 3.1.0. Decrypt such old files with `--password` (the
  trimmed password) or remove the spaces from the file.
- Scripts that relied on exit status 0 after failures in `--folder` mode, or on
  decryption replacing existing files, need `--force` or a check of the status.

## [3.1.0] - 2026-03-21

- Go rewrite of the Python tool: v3 file format with XChaCha20-Poly1305 or
  AES-256-GCM, Argon2id (4 GiB or 64 MiB), HMAC-SHA512 and streaming 64 MiB
  chunks; release binaries for linux/amd64, linux/arm64 and windows/amd64.
