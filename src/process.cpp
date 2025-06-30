
#include <frida-gum.h>

#include "gumpp.hpp"
#include "runtime.hpp"
#include "objectwrapper.hpp"
#include "string.hpp"

#include <cassert>
#include <filesystem>
#include <string>
#include <string_view>

namespace Gum {
    class ModuleImpl : public ObjectWrapper<ModuleImpl, Module, GumModule> {
    public:
        ModuleImpl(GumModule *m) {
            Runtime::ref();
            assign_handle(m);
        }

        virtual ~ModuleImpl() {
            Runtime::unref();
        }

        virtual const char *name() const override {
            return gum_module_get_name(handle);
        }

        virtual MemoryRange range() const override {
            auto range = gum_module_get_range(handle);
            MemoryRange r;
            r.base_address = GSIZE_TO_POINTER(range->base_address);
            r.size = range->size;
            return r;
        }

        virtual const char *path() const override {
            return gum_module_get_path(handle);
        }
        virtual void ensure_initialized() const override {
            gum_module_ensure_initialized(handle);
        }
        virtual void enumerate_imports(const std::function<bool(const ImportDetails &details)> &callback) const override {
            gum_module_enumerate_imports(handle, [](const GumImportDetails *details, gpointer user_data) -> gboolean {
                auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                ImportDetails detail;
                detail.type = (ImportType) details->type;
                detail.name = details->name;
                detail.module = details->module;
                detail.address = GSIZE_TO_POINTER(details->address);
                detail.slot = (void **) GSIZE_TO_POINTER(details->slot);
                return (*c)(detail); }, (void *) &callback);
        }
        virtual void enumerate_exports(const std::function<bool(const ExportDetails &details)> &callback) const override {
            gum_module_enumerate_exports(handle, [](const GumExportDetails *details, gpointer user_data) -> gboolean {
                auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                ExportDetails detail;
                detail.type = (ExportType) details->type;
                detail.name = details->name;
                detail.address = GSIZE_TO_POINTER(details->address);
                return (*c)(detail); }, (void *) &callback);
        }
        virtual void enumerate_symbols(const std::function<bool(const SymbolDetails &details)> &callback) const override {
            gum_module_enumerate_symbols(handle, [](const GumSymbolDetails *details, gpointer user_data) -> gboolean {
                auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
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
                return (*c)(detail); }, (void *) &callback);
        }
        virtual void enumerate_ranges(PageProtection prot,
                                      const std::function<bool(const RangeDetails &range)> &callback) const override {
            gum_module_enumerate_ranges(handle, (GumPageProtection) prot, [](const GumRangeDetails *details, gpointer user_data) -> gboolean {
                auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                RangeDetails detail;
                MemoryRange range;
                if (details->range) {
                    range.base_address = GSIZE_TO_POINTER(details->range->base_address);
                    range.size = details->range->size;
                }
                FileMapping file;
                if (details->file) {
                    file.path = details->file->path;
                    file.offset = details->file->offset;
                    file.size = details->file->size;
                }
                detail.range = details->range ? &range : nullptr;
                detail.protection = (PageProtection) details->protection;  
                detail.file = details->file ? &file : nullptr;
                return (*c)(detail); }, (void *) &callback);
        }
        virtual void enumerate_sections(const std::function<bool(const SectionDetails &section)> &callback) const override {
            gum_module_enumerate_sections(handle, [](const GumSectionDetails *section, gpointer user_data) -> gboolean {
                auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                SectionDetails detail;
                detail.id = section->id;
                detail.name = section->name;
                detail.address = GSIZE_TO_POINTER(section->address);
                detail.size = section->size;
                return (*c)(detail); }, (void *) &callback);
        }
        virtual void enumerate_dependencies(const std::function<bool(const DependencyDetails &details)> &callback) const override {
            gum_module_enumerate_dependencies(handle, [](const GumDependencyDetails *details, gpointer user_data) -> gboolean {
                auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                DependencyDetails detail;
                detail.name = details->name;
                detail.type = (DependencyType) details->type;
                return (*c)(detail); }, (void *) &callback);
        }
        virtual void *find_export_by_name(const char *symbol_name) const override {
            return GSIZE_TO_POINTER(gum_module_find_export_by_name(handle, symbol_name));
        }

        virtual void *find_symbol_by_name(const char *symbol_name) const override {
            return GSIZE_TO_POINTER(gum_module_find_symbol_by_name(handle, symbol_name));
        }
    };

    void *find_global_export_by_name(const char *symbol_name) {
        return GSIZE_TO_POINTER(gum_module_find_global_export_by_name(symbol_name));
    }

    Module *module_load(const char *name, std::string *error) {
        GError *gerror = NULL;
        auto m = gum_module_load(name, &gerror);
        if (error) {
            *error = gerror->message;
            g_error_free(gerror);
        }
        if (m == nullptr) {
            return nullptr;
        }
        return new ModuleImpl(m);
    }
    namespace Process {
        Module *get_main_module() {
            Runtime::ref();
            auto m = gum_process_get_main_module();
            if (m == nullptr) {
                Runtime::unref();
                return nullptr;
            }
            return new ModuleImpl(m);
        }

        Module *get_libc_module() {
            Runtime::ref();
            auto m = gum_process_get_libc_module();
            if (m == nullptr) {
                Runtime::unref();
                return nullptr;
            }
            return new ModuleImpl(m);
        }

        Module *find_module_by_name(const char *name) {
            Runtime::ref();
            auto m = gum_process_find_module_by_name(name);
            if (m == nullptr) {
                Runtime::unref();
                return nullptr;
            }
            return new ModuleImpl(m);
        }

        Module *find_module_by_address(void *address) {
            Runtime::ref();
            auto m = gum_process_find_module_by_address(GPOINTER_TO_SIZE(address));
            if (m == nullptr) {
                Runtime::unref();
                return nullptr;
            }
            return new ModuleImpl(m);
        }

        void enumerate_modules(const FoundModuleFunc &func) {
            Runtime::ref();
            gum_process_enumerate_modules(
                    [](GumModule *m, void *p) -> gboolean {
                        const auto func = (FoundModuleFunc *) p;
                        ModuleImpl impl{m};
                        return (*func)(impl);
                    },
                    (void *) &func);
            Runtime::unref();
        }

        void enumerate_ranges(PageProtection prot, const std::function<bool(const RangeDetails &range)> &callback) {
            Runtime::ref();
            gum_process_enumerate_ranges(prot, [](const GumRangeDetails *details, gpointer user_data) -> gboolean {
                                            auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                                            RangeDetails detail;
                                            MemoryRange range;
                                            if (details->range) {
                                                range.base_address = GSIZE_TO_POINTER(details->range->base_address);
                                                range.size = details->range->size;
                                            }
                                            FileMapping file;
                                            if (details->file) {
                                                file.path = details->file->path;
                                                file.offset = details->file->offset;
                                                file.size = details->file->size;
                                            }
                                            detail.range = details->range ? &range : nullptr;
                                            detail.protection = (PageProtection) details->protection;  
                                            detail.file = details->file ? &file : nullptr;
                                            return (*c)(detail); }, (void *) &callback);
            Runtime::unref();
        }
        void enumerate_malloc_ranges(const std::function<bool(const MallocRangeDetails &range)> &callback) {
            Runtime::ref();
            gum_process_enumerate_malloc_ranges(
                    [](const GumMallocRangeDetails *details, gpointer user_data) -> gboolean {
                        auto c = (std::remove_reference_t<decltype(callback)> *) user_data;
                        MallocRangeDetails detail;
                        MemoryRange range;
                        if (details->range) {
                            range.base_address = GSIZE_TO_POINTER(details->range->base_address);
                            range.size = details->range->size;
                        }
                        detail.range = details->range ? &range : nullptr;
                        return (*c)(detail);
                    },
                    (void *) &callback);
            Runtime::unref();
        }
        ProcessId get_id() {
            return gum_process_get_id();
        }
        ThreadId get_current_thread_id() {
            return gum_process_get_current_thread_id();
        }
    }// namespace Process
}// namespace Gum