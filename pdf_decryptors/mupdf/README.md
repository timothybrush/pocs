# MuPDF AES-256 key recovery

MuPDF versions before 1.28.5 generate AES-256 PDF file keys with a timestamp-seeded 48-bit linear congruential generator. `fz_memrnd()` keeps only state bits 17 through 24 for each output byte. Because `fz_srand48()` initializes the low 16 state bits to `0x330e`, only nine timestamp bits affect the output stream. A PDF therefore has only 512 candidate streams at a known stream offset.

The included `decrypt.py` enumerates all 512 streams, tests the possible file-key offsets against the known structure of `/Perms`, and writes an unencrypted PDF without either the user or owner password.

## Usage

Requirements:

- Python 3
- [`cryptography`](https://cryptography.io/)
- `mutool` on `PATH`

```bash
python3 -m pip install cryptography
python3 decrypt.py encrypted.pdf decrypted.pdf
```

Example output:

```text
[*] Reading encrypted.pdf
[+] Recovered and verified the AES-256 file key
    seed time(NULL) mod 512 = 341
    key  944f1337e8a3a13ef4c26ac4c32d29c513321b0be1b19abc8cfb5a0da8d63e15
[+] Wrote unencrypted PDF to decrypted.pdf
```

The input must use PDF security-handler revision 6 with `/AESV3`. The script handles the stream positions used for new documents, rewritten documents, and writes with ID regeneration disabled.

## Root cause

MuPDF initializes the generator from `time(NULL)`:

```c
fz_srand48(ctx, (uint32_t)time(NULL));
```

The initial state has the standard `srand48` layout:

```c
uint16_t p[3] = { 0x330e, seed, seed >> 16 };
```

`fz_memrnd()` then truncates each result to one byte:

```c
return fz_rand48_step(s, ctx->seed48 + 3) >> 17;

while (len-- > 0)
    *data++ = (unsigned char)fz_lrand48(ctx);
```

Higher state bits cannot affect lower state bits in this LCG. Each output byte comes from state bits 17 through 24, so only timestamp bits 0 through 8 can affect the generated file key.

MuPDF 1.28.5 replaced this generator with a ChaCha20-based generator seeded from operating-system entropy.
