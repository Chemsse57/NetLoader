#pragma once
#include <windows.h>
#include <oaidl.h>
#include <oleauto.h>

#define VT(iface, idx) (((void**)(*(void**)(iface)))[idx])
#define COM_RELEASE(iface) ((ULONG(STDMETHODCALLTYPE*)(void*))VT(iface, 2))(iface)

static const GUID xCLSID_CLRMetaHost = {
    0x9280188d, 0x0e8e, 0x4867,
    {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}
};
static const GUID xIID_ICLRMetaHost = {
    0xd332db9e, 0xb9b3, 0x4125,
    {0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16}
};
static const GUID xIID_ICLRRuntimeInfo = {
    0xbd39d1d2, 0xba2f, 0x486a,
    {0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91}
};
static const GUID xCLSID_CorRuntimeHost = {
    0xcb2f6723, 0xab3a, 0x11d2,
    {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};
static const GUID xIID_ICorRuntimeHost = {
    0xcb2f6722, 0xab3a, 0x11d2,
    {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};
static const GUID xIID_AppDomain = {
    0x05f696dc, 0x2b29, 0x3663,
    {0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13}
};

typedef HRESULT(STDMETHODCALLTYPE* fn_CLRCreateInstance)(
    REFCLSID clsid, REFIID riid, LPVOID* ppInterface
);

static HRESULT clr_execute(
    BYTE*  assembly_bytes,
    DWORD  assembly_size,
    char** args,
    int    argc
) {
    HRESULT hr;

    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) return E_FAIL;

    fn_CLRCreateInstance pCLRCreateInstance =
        (fn_CLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) return E_FAIL;

    void* pMetaHost = NULL;
    hr = pCLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, &pMetaHost);
    if (FAILED(hr)) return hr;

    void* pRuntimeInfo = NULL;
    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, LPCWSTR, const GUID*, void**))
        VT(pMetaHost, 3))(pMetaHost, L"v4.0.30319", &xIID_ICLRRuntimeInfo, &pRuntimeInfo);
    if (FAILED(hr)) { COM_RELEASE(pMetaHost); return hr; }

    void* pRuntimeHost = NULL;
    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, const GUID*, const GUID*, void**))
        VT(pRuntimeInfo, 9))(pRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, &pRuntimeHost);
    if (FAILED(hr)) { COM_RELEASE(pRuntimeInfo); COM_RELEASE(pMetaHost); return hr; }

    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*))VT(pRuntimeHost, 10))(pRuntimeHost);
    if (FAILED(hr)) goto cleanup;

    IUnknown* pDomainUnk = NULL;
    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, IUnknown**))
        VT(pRuntimeHost, 13))(pRuntimeHost, &pDomainUnk);
    if (FAILED(hr)) goto cleanup;

    void* pAppDomain = NULL;
    hr = pDomainUnk->lpVtbl->QueryInterface(pDomainUnk, &xIID_AppDomain, &pAppDomain);
    pDomainUnk->lpVtbl->Release(pDomainUnk);
    if (FAILED(hr)) goto cleanup;

    SAFEARRAYBOUND bound = { assembly_size, 0 };
    SAFEARRAY* pSaAsm = SafeArrayCreate(VT_UI1, 1, &bound);
    if (!pSaAsm) { hr = E_OUTOFMEMORY; goto cleanup_domain; }
    void* sa_data = NULL;
    SafeArrayAccessData(pSaAsm, &sa_data);
    memcpy(sa_data, assembly_bytes, assembly_size);
    SafeArrayUnaccessData(pSaAsm);

    void* pAssembly = NULL;
    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, SAFEARRAY*, void**))
        VT(pAppDomain, 45))(pAppDomain, pSaAsm, &pAssembly);
    SafeArrayDestroy(pSaAsm);
    if (FAILED(hr)) goto cleanup_domain;

    void* pMethodInfo = NULL;
    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, void**))
        VT(pAssembly, 16))(pAssembly, &pMethodInfo);
    if (FAILED(hr)) goto cleanup_asm;

    // Detect parameter count
    int paramCount = 0;
    {
        SAFEARRAY* psaParams = NULL;
        hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, SAFEARRAY**))
            VT(pMethodInfo, 18))(pMethodInfo, &psaParams);
        if (SUCCEEDED(hr) && psaParams) {
            long lb = 0, ub = 0;
            SafeArrayGetLBound(psaParams, 1, &lb);
            SafeArrayGetUBound(psaParams, 1, &ub);
            paramCount = (int)(ub - lb + 1);
            SafeArrayDestroy(psaParams);
        }
    }

    // Build arguments
    VARIANT vtResult;
    VariantInit(&vtResult);
    VARIANT vtObj;
    VariantInit(&vtObj);
    vtObj.vt = VT_NULL;

    SAFEARRAY* psaMethodArgs = NULL;

    if (paramCount > 0) {
        SAFEARRAYBOUND outerBound = { 1, 0 };
        psaMethodArgs = SafeArrayCreate(VT_VARIANT, 1, &outerBound);

        SAFEARRAYBOUND innerBound = { (argc > 0) ? (ULONG)argc : 0, 0 };
        SAFEARRAY* psaStrArgs = SafeArrayCreate(VT_BSTR, 1, &innerBound);

        if (argc > 0 && args != NULL) {
            for (int i = 0; i < argc; i++) {
                int wlen = MultiByteToWideChar(CP_ACP, 0, args[i], -1, NULL, 0);
                WCHAR* warg = (WCHAR*)malloc(wlen * sizeof(WCHAR));
                MultiByteToWideChar(CP_ACP, 0, args[i], -1, warg, wlen);
                BSTR bstr = SysAllocString(warg);
                free(warg);
                long idx = i;
                SafeArrayPutElement(psaStrArgs, &idx, bstr);
                SysFreeString(bstr);
            }
        }

        VARIANT vtStrArray;
        VariantInit(&vtStrArray);
        vtStrArray.vt = VT_ARRAY | VT_BSTR;
        vtStrArray.parray = psaStrArgs;
        long zero = 0;
        SafeArrayPutElement(psaMethodArgs, &zero, &vtStrArray);
    }

    // _MethodInfo::Invoke_3 at vtable index 37
    hr = ((HRESULT(STDMETHODCALLTYPE*)(void*, VARIANT, SAFEARRAY*, VARIANT*))
        VT(pMethodInfo, 37))(pMethodInfo, vtObj, psaMethodArgs, &vtResult);

    if (psaMethodArgs) SafeArrayDestroy(psaMethodArgs);

    COM_RELEASE(pMethodInfo);
cleanup_asm:
    COM_RELEASE(pAssembly);
cleanup_domain:
    COM_RELEASE(pAppDomain);
cleanup:
    COM_RELEASE(pRuntimeHost);
    COM_RELEASE(pRuntimeInfo);
    COM_RELEASE(pMetaHost);

    return hr;
}
