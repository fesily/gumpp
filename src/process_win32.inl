#pragma once
//////////////////////////////////////////////////////////////////////////////
//
//  Module Enumeration Functions (modules.cpp of detours.lib)
//
//  Microsoft Research Detours Package, Version 4.0.1
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  Module enumeration functions.
//
#ifdef _WIN32
typedef BOOL(CALLBACK *PF_DETOUR_IMPORT_FILE_CALLBACK)(_In_opt_ PVOID pContext,
                                                       _In_opt_ LPCSTR pszFile);

// Same as PF_DETOUR_IMPORT_FUNC_CALLBACK but extra indirection on last parameter.
typedef BOOL(CALLBACK *PF_DETOUR_IMPORT_FUNC_CALLBACK_EX)(_In_opt_ PVOID pContext,
                                                          _In_ DWORD nOrdinal,
                                                          _In_opt_ LPCSTR pszFunc,
                                                          _In_opt_ PVOID *ppvFunc);

static inline PBYTE RvaAdjust(_Pre_notnull_ PIMAGE_DOS_HEADER pDosHeader, _In_ DWORD raddr) {
    if (raddr != 0) {
        return ((PBYTE) pDosHeader) + raddr;
    }
    return NULL;
}

static BOOL WINAPI DetourEnumerateImportsEx(_In_opt_ HMODULE hModule,
                                            _In_opt_ PVOID pContext,
                                            _In_opt_ PF_DETOUR_IMPORT_FILE_CALLBACK pfImportFile,
                                            _In_opt_ PF_DETOUR_IMPORT_FUNC_CALLBACK_EX pfImportFunc) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hModule;
    if (hModule == NULL) {
        pDosHeader = (PIMAGE_DOS_HEADER) GetModuleHandleW(NULL);
    }

    __try {
#pragma warning(suppress : 6011)// GetModuleHandleW(NULL) never returns NULL.
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((PBYTE) pDosHeader +
                                                           pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return FALSE;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        PIMAGE_IMPORT_DESCRIPTOR iidp = (PIMAGE_IMPORT_DESCRIPTOR)
                RvaAdjust(pDosHeader,
                          pNtHeader->OptionalHeader
                                  .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                  .VirtualAddress);

        if (iidp == NULL) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        for (; iidp->OriginalFirstThunk != 0; iidp++) {

            PCSTR pszName = (PCHAR) RvaAdjust(pDosHeader, iidp->Name);
            if (pszName == NULL) {
                SetLastError(ERROR_EXE_MARKED_INVALID);
                return FALSE;
            }

            PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)
                    RvaAdjust(pDosHeader, iidp->OriginalFirstThunk);
            PVOID *pAddrs = (PVOID *)
                    RvaAdjust(pDosHeader, iidp->FirstThunk);

            if (pfImportFile != NULL) {
                if (!pfImportFile(pContext, pszName)) {
                    break;
                }
            }

            DWORD nNames = 0;
            if (pThunks) {
                for (; pThunks[nNames].u1.Ordinal; nNames++) {
                    DWORD nOrdinal = 0;
                    PCSTR pszFunc = NULL;

                    if (IMAGE_SNAP_BY_ORDINAL(pThunks[nNames].u1.Ordinal)) {
                        nOrdinal = (DWORD) IMAGE_ORDINAL(pThunks[nNames].u1.Ordinal);
                    } else {
                        pszFunc = (PCSTR) RvaAdjust(pDosHeader,
                                                    (DWORD) pThunks[nNames].u1.AddressOfData + 2);
                    }

                    if (pfImportFunc != NULL) {
                        if (!pfImportFunc(pContext,
                                          nOrdinal,
                                          pszFunc,
                                          &pAddrs[nNames])) {
                            break;
                        }
                    }
                }
                if (pfImportFunc != NULL) {
                    pfImportFunc(pContext, 0, NULL, NULL);
                }
            }
        }
        if (pfImportFile != NULL) {
            pfImportFile(pContext, NULL);
        }
        SetLastError(NO_ERROR);
        return TRUE;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return FALSE;
    }
}

static BOOL WINAPI DetourEnumerateDelayLoadImportsEx(_In_opt_ HMODULE hModule,
                                                     _In_opt_ PVOID pContext,
                                                     _In_opt_ PF_DETOUR_IMPORT_FILE_CALLBACK pfImportFile,
                                                     _In_opt_ PF_DETOUR_IMPORT_FUNC_CALLBACK_EX pfImportFunc) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hModule;
    if (hModule == NULL) {
        pDosHeader = (PIMAGE_DOS_HEADER) GetModuleHandleW(NULL);
    }

    __try {
#pragma warning(suppress : 6011)// GetModuleHandleW(NULL) never returns NULL.
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((PBYTE) pDosHeader +
                                                           pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return FALSE;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        PIMAGE_DELAYLOAD_DESCRIPTOR iidp = (PIMAGE_DELAYLOAD_DESCRIPTOR)
                RvaAdjust(pDosHeader,
                          pNtHeader->OptionalHeader
                                  .DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
                                  .VirtualAddress);

        if (iidp == NULL) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        //TODO: fix v1 version
        if (iidp->Attributes.RvaBased == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return FALSE;
        }

        for (; iidp->DllNameRVA != 0; iidp++) {

            PCSTR pszName = (PCHAR) RvaAdjust(pDosHeader, iidp->DllNameRVA);
            if (pszName == NULL) {
                SetLastError(ERROR_EXE_MARKED_INVALID);
                return FALSE;
            }

            PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)
                    RvaAdjust(pDosHeader, iidp->ImportNameTableRVA);
            PVOID *pAddrs = (PVOID *)
                    RvaAdjust(pDosHeader, iidp->ImportAddressTableRVA);

            if (pfImportFile != NULL) {
                if (!pfImportFile(pContext, pszName)) {
                    break;
                }
            }

            DWORD nNames = 0;
            if (pThunks) {
                for (; pThunks[nNames].u1.Ordinal; nNames++) {
                    DWORD nOrdinal = 0;
                    PCSTR pszFunc = NULL;

                    if (IMAGE_SNAP_BY_ORDINAL(pThunks[nNames].u1.Ordinal)) {
                        nOrdinal = (DWORD) IMAGE_ORDINAL(pThunks[nNames].u1.Ordinal);
                    } else {
                        pszFunc = (PCSTR) RvaAdjust(pDosHeader,
                                                    (DWORD) pThunks[nNames].u1.AddressOfData + 2);
                    }

                    if (pfImportFunc != NULL) {
                        if (!pfImportFunc(pContext,
                                          nOrdinal,
                                          pszFunc,
                                          &pAddrs[nNames])) {
                            break;
                        }
                    }
                }
                if (pfImportFunc != NULL) {
                    pfImportFunc(pContext, 0, NULL, NULL);
                }
            }
        }
        if (pfImportFile != NULL) {
            pfImportFile(pContext, NULL);
        }
        SetLastError(NO_ERROR);
        return TRUE;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        SetLastError(ERROR_EXE_MARKED_INVALID);
        return FALSE;
    }
}
#endif