#!/usr/bin/env python3
"""
CLR Loader - Assembly Encryptor
Encrypts .NET assembly with AES-256-CBC.
Key derivation matches Windows CryptoAPI CryptDeriveKey(CALG_AES_256, SHA-256(passphrase)).

Usage:
    python encrypt.py <assembly.exe> <passphrase> [-o output_dir]
"""

import os
import sys
import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_assembly(input_path, passphrase, output_dir="."):
    # Read assembly
    with open(input_path, "rb") as f:
        plaintext = f.read()

    print(f"[*] Input: {input_path} ({len(plaintext)} bytes)")

    # Derive key: SHA-256 of passphrase (matches CryptoAPI CryptDeriveKey)
    key = hashlib.sha256(passphrase.encode("utf-8")).digest()  # 32 bytes

    # Random IV
    iv = os.urandom(16)

    # Encrypt with AES-256-CBC + PKCS7 padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Output: [IV (16 bytes)][ciphertext]
    output_data = iv + ciphertext

    # Write encrypted file
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    output_path = os.path.join(output_dir, f"{base_name}.enc")

    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(output_data)

    print(f"[+] Output: {output_path} ({len(output_data)} bytes)")
    print(f"[+] Passphrase: {passphrase}")
    print(f"[+] Key (SHA-256): {key.hex()}")
    print(f"[+] IV: {iv.hex()}")
    print(f"[*] Serve with: cd {output_dir} && python3 -m http.server 8080")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt .NET assembly for CLR Loader")
    parser.add_argument("assembly", help="Path to .NET assembly (.exe or .dll)")
    parser.add_argument("passphrase", help="Encryption passphrase")
    parser.add_argument("-o", "--output", default="payload", help="Output directory")
    args = parser.parse_args()

    if not os.path.isfile(args.assembly):
        print(f"[-] File not found: {args.assembly}")
        sys.exit(1)

    encrypt_assembly(args.assembly, args.passphrase, args.output)
