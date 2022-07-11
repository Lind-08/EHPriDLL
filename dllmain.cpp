// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "framework.h"

bool flag = false;
HOOK_TRACE_INFO hLoadLibraryWHook = { NULL };
HOOK_TRACE_INFO hGetDefaultPrinterWHook = { NULL };
HOOK_TRACE_INFO hEnumPrintersWHook = { NULL };
HOOK_TRACE_INFO hOpenPrinterWHook = { NULL };

HANDLE (WINAPI *TrueCreateFileW)(
LPCWSTR               lpFileName,
DWORD                 dwDesiredAccess,
DWORD                 dwShareMode,
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
DWORD                 dwCreationDisposition,
DWORD                 dwFlagsAndAttributes,
HANDLE                hTemplateFile) 
= CreateFileW;

HANDLE WINAPI TramplinedCreateFileW(
    LPCWSTR a0,
    DWORD a1,
    DWORD a2,
    LPSECURITY_ATTRIBUTES a3,
    DWORD a4,
    DWORD a5,
    HANDLE a6)
{
    OutputDebugStringW(L"TramplinedCreateFileW invoked");
    OutputDebugStringW((std::wstring(L"Path: ") + std::wstring(a0)).c_str());
    return TrueCreateFileW(a0,a1,a2,a3,a4,a5,a6);
}

BOOL (WINAPI *TrueEnumPrintersW)(
    DWORD   Flags,
    LPTSTR  Name,
    DWORD   Level,
    LPBYTE  pPrinterEnum,
    DWORD   cbBuf,
    LPDWORD pcbNeeded,
    LPDWORD pcReturned);

BOOL (WINAPI *TrueGetDefaultPrinterW)(
    LPTSTR  pszBuffer,
    LPDWORD pcchBuffer);

BOOL (WINAPI *TrueOpenPrinterW)(
    LPTSTR             pPrinterName,
    LPHANDLE           phPrinter,
    LPPRINTER_DEFAULTS pDefault
);

HMODULE (WINAPI *TrueLoadLibraryW)(
    LPCWSTR lpLibFileName
) = LoadLibraryW;

BOOL WINAPI TramplinedEnumPrintersW(
    DWORD   Flags,
    LPTSTR  Name,
    DWORD   Level,
    LPBYTE  pPrinterEnum,
    DWORD   cbBuf,
    LPDWORD pcbNeeded,
    LPDWORD pcReturned
)
{
    OutputDebugStringW(L"TramplinedEnumPrinters invoked");
    return TrueEnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
}

BOOL WINAPI TramplinedGetDefaultPrinterW(
    LPTSTR  pszBuffer,
    LPDWORD pcchBuffer
)
{
    OutputDebugStringW(L"TramplinedGetDefaultPrinterW invoked");
    return TrueGetDefaultPrinterW(pszBuffer, pcchBuffer);
}

BOOL WINAPI TramplinedOpenPrinterW(
    LPTSTR             pPrinterName,
    LPHANDLE           phPrinter,
    LPPRINTER_DEFAULTS pDefault
)
{
    OutputDebugStringW(L"TramplinedOpenPrinterW invoked");
    return TrueOpenPrinterW(pPrinterName, phPrinter, pDefault);
}

void AttachHooks()
{
    NTSTATUS result = LhInstallHook(
		TrueGetDefaultPrinterW,
		TramplinedGetDefaultPrinterW,
		NULL,
		&hGetDefaultPrinterWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		OutputDebugStringW((std::wstring(L"Failed to install hook: ") + s).c_str());
	}
	else 
	{
		OutputDebugStringW(L"Hook GetDefaultPrinterW installed successfully");
	}

    result = LhInstallHook(
		TrueEnumPrintersW,
		TramplinedEnumPrintersW,
		NULL,
		&hEnumPrintersWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		OutputDebugStringW((std::wstring(L"Failed to install hook: ") + s).c_str());
	}
	else 
	{
		OutputDebugStringW(L"Hook EnumPrintersW installed successfully");
	}

    result = LhInstallHook(
		TrueOpenPrinterW,
		TramplinedOpenPrinterW,
		NULL,
		&hOpenPrinterWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		OutputDebugStringW((std::wstring(L"Failed to install hook: ") + s).c_str());
	}
	else 
	{
		OutputDebugStringW(L"Hook OpenPrinterW installed successfully");
	}
}

void DetachHooks()
{
    LhUninstallAllHooks();
}

HMODULE WINAPI TramplinedLoadLibraryW (
    LPCWSTR lpLibFileName
)
{
    OutputDebugStringW(L"TramplinedLoadLibraryW invoked");
    OutputDebugStringW((std::wstring(L"LibFileName: ") + std::wstring(lpLibFileName)).c_str());
    std::wstring libFileName(lpLibFileName);
    if (libFileName.find(L"winspool.drv") != std::wstring::npos)
    {
        if (!flag)
        {
            auto hModule = TrueLoadLibraryW(lpLibFileName);
            if (hModule)
            {
                TrueGetDefaultPrinterW = (BOOL (WINAPI*)(LPTSTR, LPDWORD))GetProcAddress(hModule, "GetDefaultPrinterW");
                TrueEnumPrintersW = (BOOL (WINAPI *)(DWORD, LPTSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD ))GetProcAddress(hModule, "EnumPrintersW");
                TrueOpenPrinterW = (BOOL (WINAPI *)(LPTSTR, LPHANDLE, LPPRINTER_DEFAULTS)) GetProcAddress(hModule, "OpenPrinterW");
                AttachHooks();
                flag = true;
            }
            return hModule;
        }
    }
    return TrueLoadLibraryW(lpLibFileName);
};

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
    auto hModule = TrueLoadLibraryW(L"kernel32.dll");
    if (!hModule)
    {
        OutputDebugStringW(L"Can't load kernel32.dll");
    }

    TrueLoadLibraryW = (HMODULE (WINAPI*)(LPCWSTR))GetProcAddress(hModule, "LoadLibraryW");

    NTSTATUS result = LhInstallHook(
		TrueLoadLibraryW,
		TramplinedLoadLibraryW,
		NULL,
		&hLoadLibraryWHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		OutputDebugStringW((std::wstring(L"Failed to install hook: ") + s).c_str());
	}
	else 
	{
		OutputDebugStringW(L"Hook LoadLibraryW installed successfully");
	}
    if (inRemoteInfo->UserDataSize == sizeof(bool))
	{
        result = RhWakeUpProcess();
        if (FAILED(result))
	    {
		    std::wstring s(RtlGetLastErrorString());
		    OutputDebugStringW((std::wstring(L"Error: ") + s).c_str());
	    }
	} 
}