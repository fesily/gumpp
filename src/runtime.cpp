#include "runtime.hpp"

#include <frida-gum.h>
#ifdef HAVE_WINDOWS
#include <cstdio>
#include <filesystem>
#include <windows.h>
#include <Dbghelp.h>
#endif

namespace Gum {
volatile int Runtime::ref_count = 0;
#ifdef _WIN32
struct _GumDbghelpImpl;
extern "C" _GumDbghelpImpl* gum_dbghelp_impl_try_obtain(void);
inline std::string searchpath(bool SymBuildPath, bool SymUseSymSrv) {
  // Build the sym-path:
  if (SymBuildPath) {
    std::string searchpath;
    searchpath.reserve(4096);
    searchpath.append(".;");
    std::error_code ec;
    auto current_path = std::filesystem::current_path(ec);
    if (!ec) {
      searchpath.append(current_path.string().c_str());
      searchpath += ';';
    }
    const size_t nTempLen = 1024;
    char szTemp[nTempLen];

    // Now add the path for the main-module:
    if (GetModuleFileNameA(NULL, szTemp, nTempLen) > 0) {
      std::filesystem::path path(szTemp);
      searchpath.append(path.parent_path().string());
      searchpath += ';';
    }
    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", szTemp, nTempLen) > 0) {
      szTemp[nTempLen - 1] = 0;
      searchpath.append(szTemp);
      searchpath += ';';
    }
    if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", szTemp, nTempLen) >
        0) {
      szTemp[nTempLen - 1] = 0;
      searchpath.append(szTemp);
      searchpath += ';';
    }
    if (GetEnvironmentVariableA("SYSTEMROOT", szTemp, nTempLen) > 0) {
      szTemp[nTempLen - 1] = 0;
      searchpath.append(szTemp);
      searchpath += ';';
      searchpath.append(szTemp);
      searchpath.append("\\system32;");
    }

    if (SymUseSymSrv) {
      if (GetEnvironmentVariableA("SYSTEMDRIVE", szTemp, nTempLen) > 0) {
        szTemp[nTempLen - 1] = 0;
        searchpath.append("SRV*");
        searchpath.append(szTemp);
        searchpath.append(
            "\\websymbols*https://msdl.microsoft.com/download/symbols;");
      } else
        searchpath.append(
            "SRV*c:\\websymbols*https://msdl.microsoft.com/download/symbols;");
    }
    return searchpath;
  }  // if SymBuildPath
  return {};
}
void init_gdbhelp() {
  gum_dbghelp_impl_try_obtain();
  HANDLE proc = GetCurrentProcess();
#ifndef NDEBUG
  char oldpath[2048];
  SymGetSearchPath(proc, oldpath, sizeof(oldpath));
  printf("SymGetSearchPath:%s", oldpath);
#endif
  SymSetSearchPath(proc, searchpath(true, true).c_str());
}
#else
void init_gdbhelp() {}
#endif

static void init() {
  gum_init_embedded();
  init_gdbhelp();
}

static void deinit() {
  gum_deinit_embedded();
}

#if defined(HAVE_WINDOWS) && !defined(GUMPP_STATIC)

extern "C" BOOL WINAPI DllMain(HINSTANCE inst_dll,
                               DWORD reason,
                               LPVOID reserved) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      init();
      break;
    case DLL_PROCESS_DETACH:
      if (reserved == NULL)
        deinit();
      break;
  }

  return TRUE;
}

void Runtime::ref() {}

void Runtime::unref() {}

#else

void Runtime::ref() {
  if (g_atomic_int_add(&ref_count, 1) == 0)
    init();
}

void Runtime::unref() {
  if (g_atomic_int_dec_and_test(&ref_count))
    deinit();
}
#endif

void runtime_init() {
  Runtime::ref();
}
void runtime_deinit() {
  Runtime::unref();
}
}  // namespace Gum
