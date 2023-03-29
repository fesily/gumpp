
#include <frida-gum.h>

#include "gumpp.hpp"
#include "runtime.hpp"
#include "string.hpp"

#ifdef _WIN32
#include <Windows.h>
#include <DbgHelp.h>
#include <shlwapi.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")
#include "process_win32.inl"
#endif

#include <cassert>
#include <filesystem>
#include <string>
#include <string_view>

namespace Gum {
    struct ModuleDetailsImpl : ModuleDetails {
        const GumModuleDetails *details;

        ModuleDetailsImpl(const GumModuleDetails *d)
            : details{d} {}

        virtual ~ModuleDetailsImpl() = default;

        virtual const char *name() const { return details->name; }

        virtual MemoryRange range() const {
            return MemoryRange{GSIZE_TO_POINTER(details->range->base_address),
                               details->range->size};
        }

        virtual const char *path() const { return details->path; }
    };

    void Process::enumerate_modules(const FoundModuleFunc &func) {
        Runtime::ref();
        gum_process_enumerate_modules(
                [](const GumModuleDetails *details, void *p) -> gboolean {
                    const auto func = (FoundModuleFunc *) p;
                    ModuleDetailsImpl impl{details};
                    return (*func)(impl);
                },
                (void *) &func);
        Runtime::unref();
    }

#ifdef _WIN32
    inline bool is_target_symbol(PSYMBOL_INFO pSymbol, HMODULE hMod) {
        enum {
            SymTagFunction = 5,
            SymTagData = 7,
            SymTagPublicSymbol = 10,
        };
#ifndef SYMFLAG_PUBLIC_CODE
#define SYMFLAG_PUBLIC_CODE 0x00400000
#endif
        // skip public code
        if (pSymbol->Flags & SYMFLAG_PUBLIC_CODE) {
            return false;
        }
        if ((HMODULE) pSymbol->ModBase != hMod) {
            return false;
        }

        return pSymbol->Tag == SymTagFunction || pSymbol->Tag == SymTagPublicSymbol ||
               pSymbol->Tag == SymTagData;
    }
#endif
    namespace Process {
        void *module_find_symbol_by_name(const char *module_name, const char *symbol_name) {
            assert(module_name != nullptr);
#ifndef _WIN32
            Runtime::ref();
            struct {
                const char *name;
                GumAddress address;
            } ctx{symbol_name, 0};
            gum_module_enumerate_symbols(
                    module_name,
                    [](const GumSymbolDetails *details, gpointer user_data) -> gboolean {
                        auto pctx = (decltype(ctx) *) user_data;
                        if (details->address && strcmp(details->name, pctx->name) == 0) {
                            pctx->address = details->address;
                            return FALSE;
                        }
                        return TRUE;
                    },
                    (void *) &ctx);
            Runtime::unref();
            return GSIZE_TO_POINTER(ctx.address);
#else
            HMODULE hmod = LoadLibraryExA(module_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (!hmod)
                return nullptr;

            void *result = NULL;

            std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)> hMod{
                    hmod, &FreeLibrary};

            auto moduleName = std::filesystem::path(module_name)
                                      .filename()
                                      .replace_extension()
                                      .string();

            std::unique_ptr<char[]> pattern;
            size_t len = 0;
            auto proc = GetCurrentProcess();
            len = moduleName.size() + strlen(symbol_name) + 1 + 1;
            pattern = std::make_unique<char[]>(len);
            snprintf(pattern.get(), len, "%s!%s", moduleName.c_str(), symbol_name);
            ULONG64 buffer[(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR) + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
            PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;

            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSymbol->MaxNameLen = MAX_SYM_NAME;

            if (SymFromName(proc, pattern.get(), pSymbol)) {
                if (is_target_symbol(pSymbol, hMod.get())) {
                    return (void *) pSymbol->Address;
                }
            }
            std::tuple<void *&, HMODULE> ctx{result, (HMODULE) hMod.get()};
            SymEnumSymbolsEx(
                    proc, 0, pattern.get(),
                    [](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL {
                        auto &[result, hMod] = *(decltype(ctx) *) UserContext;
                        if (is_target_symbol(pSymInfo, hMod)) {
                            result = (void *) pSymInfo->Address;
                            return FALSE;
                        }
                        return TRUE;
                    },
                    (void *) &ctx, 1);
            return result;
#endif
        }

        void *module_find_export_by_name(const char *module_name, const char *symbol_name) {
            auto address = GSIZE_TO_POINTER(
                    gum_module_find_export_by_name(module_name, symbol_name));
#ifndef _WIN32
            gchar *path;
            if (gum_process_resolve_module_pointer(address, &path, nullptr)) {
                if (std::string_view(path).find(module_name) == std::string_view::npos) {
                    address = 0;
                }
                g_free(path);
            }
#endif
            return address;
        }

        bool module_load(const char *name, std::string *error) {
            GError *gerror = NULL;
            if (gum_module_load(name, &gerror)) {
                return true;
            }
            if (error)
                *error = gerror->message;
            g_error_free(gerror);
            return false;
        }

        void module_enumerate_export(
                const char *module_name,
                const std::function<bool(const ExportDetails &details)> &callback) {
            struct {
                const std::function<bool(const ExportDetails &details)> &callback;
            } ctx{callback};
            gum_module_enumerate_exports(
                    module_name,
                    [](const GumExportDetails *details, gpointer user_data) -> gboolean {
                        auto c = (decltype(ctx) *) user_data;
                        ExportDetails detail;
                        detail.type = (ExportType) details->type;
                        detail.name = details->name;
                        detail.address = GSIZE_TO_POINTER(details->address);
                        return c->callback(detail);
                        ;
                    },
                    (void *) &ctx);
        }
        void module_enumerate_import(
                const char *module_name,
                const std::function<bool(const ImportDetails &details)> &callback) {

#ifdef _WIN32
            struct {
                decltype(callback) callback;
                const char *current_file_name;
            } ctx{callback};
            auto hmod = GetModuleHandleA(module_name);
            if (!hmod) return;
            auto file_cb = [](void *pContext, LPCSTR pszFile) -> BOOL {
                auto c = (decltype(ctx) *) pContext;
                c->current_file_name = pszFile;
                return true;
            };
            auto func_cb = [](PVOID pContext, DWORD nOrdinal, LPCSTR pszFunc, PVOID *ppvFunc) -> BOOL {
                if (!pszFunc || !ppvFunc) return true;
                auto c = (decltype(ctx) *) pContext;
                ImportDetails details;
                details.type = ImportType::UNKNOWN;
                details.name = pszFunc;
                details.module = c->current_file_name;
                details.address = GSIZE_TO_POINTER(gum_module_find_export_by_name(c->current_file_name, pszFunc));
                details.slot = ppvFunc;
                return c->callback(details);
            };
            DetourEnumerateImportsEx(hmod, (void *) &ctx, file_cb, func_cb);
            DetourEnumerateDelayLoadImportsEx(hmod, (void *) &ctx, file_cb, func_cb);
#else
            struct {
                const std::function<bool(const ImportDetails &details)> &callback;
            } ctx{callback};
            gum_module_enumerate_imports(
                    module_name,
                    [](const GumImportDetails *details, gpointer user_data) -> gboolean {
                        auto c = (decltype(ctx) *) user_data;
                        ImportDetails detail;
                        detail.type = (ImportType) details->type;
                        detail.name = details->name;
                        detail.module = details->module;
                        detail.address = GSIZE_TO_POINTER(details->address);
                        detail.slot = (void **) GSIZE_TO_POINTER(details->slot);
                        return c->callback(detail);
                    },
                    (void *) &ctx);
#endif
        }

        void module_enumerate_symbols(
                const char *module_name,
                const std::function<bool(const SymbolDetails &details)> &callback) {
            struct {
                const std::function<bool(const SymbolDetails &details)> &callback;
            } ctx{callback};
            gum_module_enumerate_symbols(
                    module_name,
                    [](const GumSymbolDetails *details, gpointer user_data) -> gboolean {
                        auto c = (decltype(ctx) *) user_data;
                        SymbolDetails detail;
                        detail.is_global = details->is_global;
                        detail.type = (SymbolType) details->type;
                        SymbolSection section;
                        if (details->section) {
                            section.id = details->section->id;
                            section.protection = (PageProtection) details->section->protection;
                        }
                        detail.section = details->section ? &section : nullptr;
                        detail.name = details->name;
                        detail.address = GSIZE_TO_POINTER(details->address);
                        detail.size = details->size;
                        return c->callback(detail);
                    },
                    (void *) &ctx);
        }

        ProcessId get_id() {
            return gum_process_get_id();
        }

        ThreadId get_current_thread_id() {
            return gum_process_get_current_thread_id();
        }
    }// namespace Process
}// namespace Gum