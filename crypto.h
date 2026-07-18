#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// ============================================================
// AES-256-CBC decryption via CryptoAPI
//
// Input format: [IV 16 bytes][ciphertext...]
// Key derivation: SHA-256(passphrase) -> raw 32-byte AES key
// Must match encrypt.py key derivation
// ============================================================
static BOOL decrypt_payload(
    BYTE*       enc_buf,
    DWORD       enc_size,
    const char* passphrase,
    BYTE**      out_buf,
    DWORD*      out_size
) {
    if (enc_size <= 16) return FALSE; // Must have at least IV

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY  hKey  = 0;
    BOOL       ok    = FALSE;

    // Extract IV (first 16 bytes)
    BYTE iv[16];
    memcpy(iv, enc_buf, 16);
    BYTE* ciphertext  = enc_buf + 16;
    DWORD cipher_size = enc_size - 16;

    // Acquire crypto context
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return FALSE;

    // Hash passphrase with SHA-256
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto done;

    if (!CryptHashData(hHash, (BYTE*)passphrase, (DWORD)strlen(passphrase), 0))
        goto done;

    // Derive AES-256 key from hash
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
        goto done;

    // Set IV
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
        goto done;

    // Set CBC mode (should be default but explicit)
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0))
        goto done;

    // Allocate output and copy ciphertext
    *out_buf = (BYTE*)malloc(cipher_size);
    if (!*out_buf) goto done;
    memcpy(*out_buf, ciphertext, cipher_size);
    *out_size = cipher_size;

    // Decrypt in place
    if (!CryptDecrypt(hKey, 0, TRUE, 0, *out_buf, out_size)) {
        free(*out_buf);
        *out_buf = NULL;
        *out_size = 0;
        goto done;
    }

    ok = TRUE;

done:
    if (hKey)  CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ok;
}
