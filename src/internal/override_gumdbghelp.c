/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
#ifdef _WIN32
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include "frida-gum.h"
typedef void (*GumDestructorFunc)(void);
GUM_API void _gum_register_destructor(GumDestructorFunc destructor);

struct _GumDbghelpImplPrivate {
  HMODULE module;
};

static gpointer do_init(gpointer data);
static void do_deinit(void);

static HMODULE load_dbghelp(void);

static void gum_dbghelp_impl_lock(void);
static void gum_dbghelp_impl_unlock(void);

#define INIT_IMPL_FUNC(func)                                    \
  *((gpointer*)(&impl->func)) =                                 \
      GSIZE_TO_POINTER(GetProcAddress(mod, G_STRINGIFY(func))); \
  g_assert(impl->func != NULL)

typedef struct _GumDbghelpImpl GumDbghelpImpl;
typedef struct _GumDbghelpImplPrivate GumDbghelpImplPrivate;

struct _GumDbghelpImpl {
  BOOL(WINAPI* StackWalk64)
  (DWORD MachineType,
   HANDLE hProcess,
   HANDLE hThread,
   LPSTACKFRAME64 StackFrame,
   PVOID ContextRecord,
   PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
   PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
   PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
   PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
  DWORD(WINAPI* SymSetOptions)(DWORD SymOptions);
  BOOL(WINAPI* SymInitialize)
  (HANDLE hProcess, PCSTR UserSearchPath, BOOL fInvadeProcess);
  BOOL(WINAPI* SymCleanup)(HANDLE hProcess);
  BOOL(WINAPI* SymEnumSymbols)
  (HANDLE hProcess,
   ULONG64 BaseOfDll,
   PCSTR Mask,
   PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
   PVOID UserContext);
  BOOL(WINAPI* SymFromAddr)
  (HANDLE hProcess,
   DWORD64 Address,
   PDWORD64 Displacement,
   PSYMBOL_INFO Symbol);
  PVOID(WINAPI* SymFunctionTableAccess64)(HANDLE hProcess, DWORD64 AddrBase);
  BOOL(WINAPI* SymGetLineFromAddr64)
  (HANDLE hProcess,
   DWORD64 qwAddr,
   PDWORD pdwDisplacement,
   PIMAGEHLP_LINE64 Line64);
  DWORD64(WINAPI* SymLoadModuleExW)
  (HANDLE hProcess,
   HANDLE hFile,
   PCWSTR ImageName,
   PCWSTR ModuleName,
   DWORD64 BaseOfDll,
   DWORD DllSize,
   PMODLOAD_DATA Data,
   DWORD Flags);
  DWORD64(WINAPI* SymGetModuleBase64)(HANDLE hProcess, DWORD64 qwAddr);
  BOOL(WINAPI* SymGetModuleInfo)
  (HANDLE hProcess, DWORD dwAddr, PIMAGEHLP_MODULE ModuleInfo);
  BOOL(WINAPI* SymGetTypeInfo)
  (HANDLE hProcess,
   DWORD64 ModBase,
   ULONG TypeId,
   IMAGEHLP_SYMBOL_TYPE_INFO GetType,
   PVOID pInfo);

  void (*Lock)(void);
  void (*Unlock)(void);

  /*< private */
  GumDbghelpImplPrivate* priv;
};

GumDbghelpImpl* gum_dbghelp_impl_try_obtain(void) {
  static GOnce init_once = G_ONCE_INIT;

  g_once(&init_once, do_init, NULL);

  return init_once.retval;
}

static gpointer do_init(gpointer data) {
  HMODULE mod;
  GumDbghelpImpl* impl;

  mod = load_dbghelp();
  if (mod == NULL)
    return NULL;

  impl = g_slice_new0(GumDbghelpImpl);
  impl->priv = g_slice_new(GumDbghelpImplPrivate);
  impl->priv->module = mod;

  INIT_IMPL_FUNC(StackWalk64);
  INIT_IMPL_FUNC(SymSetOptions);
  INIT_IMPL_FUNC(SymInitialize);
  INIT_IMPL_FUNC(SymCleanup);
  INIT_IMPL_FUNC(SymEnumSymbols);
  INIT_IMPL_FUNC(SymFromAddr);
  INIT_IMPL_FUNC(SymFunctionTableAccess64);
  INIT_IMPL_FUNC(SymGetLineFromAddr64);
  INIT_IMPL_FUNC(SymLoadModuleExW);
  INIT_IMPL_FUNC(SymGetModuleBase64);
  INIT_IMPL_FUNC(SymGetModuleInfo);
  INIT_IMPL_FUNC(SymGetTypeInfo);

  impl->Lock = gum_dbghelp_impl_lock;
  impl->Unlock = gum_dbghelp_impl_unlock;

  impl->SymInitialize(GetCurrentProcess(), NULL, TRUE);

  _gum_register_destructor(do_deinit);

  return impl;
}

static void do_deinit(void) {
  GumDbghelpImpl* impl;

  impl = gum_dbghelp_impl_try_obtain();
  g_assert(impl != NULL);

  impl->SymCleanup(GetCurrentProcess());

  FreeLibrary(impl->priv->module);
  g_slice_free(GumDbghelpImplPrivate, impl->priv);
  g_slice_free(GumDbghelpImpl, impl);
}

static HMODULE load_dbghelp(void) {
  HMODULE mod;
  if (GetModuleHandleExW(0, L"dbghelp.dll", &mod)) {
    return mod;
  }
  BOOL success G_GNUC_UNUSED;
  DWORD length G_GNUC_UNUSED;
  WCHAR path[MAX_PATH + 1] = {
      0,
  };
  WCHAR* filename;

  success = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               GUM_FUNCPTR_TO_POINTER(load_dbghelp), &mod);
  g_assert(success);

  length = GetModuleFileNameW(mod, path, MAX_PATH);
  g_assert(length != 0);

  filename = wcsrchr(path, L'\\');
  g_assert(filename != NULL);
  filename++;
  wcscpy(filename, L"dbghelp.dll");

  return LoadLibraryW(path);
}

static GMutex _gum_dbghelp_mutex;

static void gum_dbghelp_impl_lock(void) {
  g_mutex_lock(&_gum_dbghelp_mutex);
}

static void gum_dbghelp_impl_unlock(void) {
  g_mutex_unlock(&_gum_dbghelp_mutex);
}
#endif
