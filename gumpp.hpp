#ifndef __GUMPP_HPP__
#define __GUMPP_HPP__

#if !defined(GUMPP_STATIC) && defined(WIN32)
#ifdef GUMPP_EXPORTS
#define GUMPP_API __declspec(dllexport)
#else
#define GUMPP_API __declspec(dllimport)
#endif
#else
#define GUMPP_API
#endif

#define GUMPP_CAPI extern "C" GUMPP_API

#define GUMPP_MAX_BACKTRACE_DEPTH 16
#define GUMPP_MAX_PATH 260
#define GUMPP_MAX_SYMBOL_NAME 2048

#include <cstddef>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
namespace Gum {
    template<typename T>
    class RefPtr;
    struct InvocationContext;
    struct InvocationListener;
    struct NoLeaveInvocationListener;
    struct CpuContext;
    struct ReturnAddressArray;

    struct Object {
        virtual ~Object() {}

        virtual void ref() = 0;
        virtual void unref() = 0;
        virtual void *get_handle() const = 0;
    };

    struct String : public Object {
        virtual const char *c_str() = 0;
        virtual size_t length() const = 0;
    };

    struct PtrArray : public Object {
        virtual int length() = 0;
        virtual void *nth(int n) = 0;
    };

    struct Interceptor : public Object {
        virtual bool attach(void *function_address, InvocationListener *listener, void *listener_function_data = 0) = 0;
        virtual void detach(InvocationListener *listener) = 0;

        virtual bool attach(void *function_address, NoLeaveInvocationListener *listener, void *listener_function_data = 0) = 0;
        virtual void detach(NoLeaveInvocationListener *listener) = 0;

        virtual void replace(void *function_address, void *replacement_address, void *replacement_data = 0, void **origin_function = 0) = 0;
        virtual void revert(void *function_address) = 0;

        virtual void begin_transaction() = 0;
        virtual void end_transaction() = 0;

        virtual void ignore_current_thread() = 0;
        virtual void unignore_current_thread() = 0;

        virtual void ignore_other_threads() = 0;
        virtual void unignore_other_threads() = 0;
    };

    RefPtr<Interceptor> Interceptor_obtain(void);

    std::unique_ptr<InvocationContext> get_current_invocation();

    struct InvocationContext {
        virtual ~InvocationContext() {}

        virtual void *get_function() const = 0;

        template<typename T>
        T get_nth_argument(unsigned int n) const {
            return reinterpret_cast<T>(get_nth_argument_ptr(n));
        }
        virtual void *get_nth_argument_ptr(unsigned int n) const = 0;
        virtual void replace_nth_argument(unsigned int n, void *value) = 0;
        template<typename T>
        T get_return_value() const {
            return static_cast<T>(get_return_value_ptr());
        }
        virtual void *get_return_value_ptr() const = 0;

        virtual unsigned int get_thread_id() const = 0;

        template<typename T>
        T *get_listener_thread_data() const {
            return static_cast<T *>(get_listener_thread_data_ptr(sizeof(T)));
        }
        virtual void *get_listener_thread_data_ptr(size_t required_size) const = 0;
        template<typename T>
        T *get_listener_function_data() const {
            return static_cast<T *>(get_listener_function_data_ptr());
        }
        virtual void *get_listener_function_data_ptr() const = 0;
        template<typename T>
        T *get_listener_invocation_data() const {
            return static_cast<T *>(get_listener_invocation_data_ptr(sizeof(T)));
        }
        virtual void *get_listener_invocation_data_ptr(
                size_t required_size) const = 0;

        template<typename T>
        T *get_replacement_data() const {
            return static_cast<T *>(get_replacement_data_ptr());
        }
        virtual void *get_replacement_data_ptr() const = 0;

        virtual CpuContext *get_cpu_context() const = 0;
    };

    struct InvocationListener {
        virtual ~InvocationListener() {}

        virtual void on_enter(InvocationContext *context) = 0;
        virtual void on_leave(InvocationContext *context) = 0;
    };

    struct NoLeaveInvocationListener {
        virtual ~NoLeaveInvocationListener() {}

        virtual void on_enter(InvocationContext *context) = 0;
    };

    struct Backtracer : public Object {
        virtual void generate(const CpuContext *cpu_context, ReturnAddressArray &return_addresses) const = 0;
    };

    RefPtr<Backtracer> Backtracer_make_accurate();
    RefPtr<Backtracer> Backtracer_make_fuzzy();

    typedef void *ReturnAddress;

    struct ReturnAddressArray {
        unsigned int len;
        ReturnAddress items[GUMPP_MAX_BACKTRACE_DEPTH];
    };

    struct ReturnAddressDetails {
        ReturnAddress address;
        char module_name[GUMPP_MAX_PATH + 1];
        char function_name[GUMPP_MAX_SYMBOL_NAME + 1];
        char file_name[GUMPP_MAX_PATH + 1];
        unsigned int line_number;
        unsigned int column;
    };

    GUMPP_CAPI bool ReturnAddressDetails_from_address(
            ReturnAddress address,
            ReturnAddressDetails &details);

    RefPtr<PtrArray> find_matching_functions_array(const char *str);
    RefPtr<String> get_function_name_from_addr(void *addr);

    template<typename T>
    class RefPtr {
    public:
        RefPtr(T *ptr_)
            : ptr(ptr_) {}
        explicit RefPtr(const RefPtr<T> &other)
            : ptr(other.ptr) {
            if (ptr)
                ptr->ref();
        }

        template<class U>
        RefPtr(const RefPtr<U> &other)
            : ptr(other.operator->()) {
            if (ptr)
                ptr->ref();
        }

        RefPtr()
            : ptr(0) {}

        bool is_null() const { return ptr == 0 || ptr->get_handle() == 0; }

        RefPtr &operator=(const RefPtr &other) {
            RefPtr tmp(other);
            swap(*this, tmp);
            return *this;
        }

        RefPtr &operator=(T *other) {
            RefPtr tmp(other);
            swap(*this, tmp);
            return *this;
        }

        T *operator->() const { return ptr; }

        T &operator*() const { return *ptr; }

        operator T *() { return ptr; }

        T *get() const { return ptr; }

        static void swap(RefPtr &a, RefPtr &b) {
            T *tmp = a.ptr;
            a.ptr = b.ptr;
            b.ptr = tmp;
        }

        ~RefPtr() {
            if (ptr)
                ptr->unref();
        }

    private:
        T *ptr;
    };
    struct ModuleDetails;
    struct DebugSymbolDetails {
        virtual ~DebugSymbolDetails() = default;
        virtual void *address() const = 0;
        virtual const char *module_name() const = 0;
        virtual const char *symbol_name() const = 0;
        virtual const char *file_name() const = 0;
        virtual uint32_t line_number() const = 0;
        virtual uint32_t column() const = 0;
    };
    struct MemoryRange;
    namespace SymbolUtil {
        std::unique_ptr<DebugSymbolDetails> details_from_address(void *addr);
        std::optional<MemoryRange> function_range_from_address(void *addr);
        void *find_function_end(void *addr, size_t max_size);
        inline bool is_public_code(void *addr) {
#ifdef _WIN32
            uint8_t *byte = (uint8_t *) addr;
#if defined(_M_AMD64)
            if (byte[0] == 0xE9 || byte[0] == 0xEB)
                return true;
            if (byte[0] == 0xFF)
                if ((byte[1] & 0x07) == 4 || (byte[1] & 0x07) == 5)
                    return true;
#elif defined(_M_IX86)
            if (byte[0] == 0xE9 || byte[0] == 0xEA || byte[0] == 0xEB)
                return true;
            if (byte[0] == 0xFF)
                if ((byte[1] & 0x07) == 4 || (byte[1] & 0x07) == 5)
                    return true;
#else
#error "unsupport"
#endif
#endif
            return false;
        }
        void *find_function(const char *name);

        inline std::vector<void *> find_matching_functions(const char *str, bool skip_public_code) {
            RefPtr<PtrArray> functions =
                    RefPtr<PtrArray>(find_matching_functions_array(str));
            std::vector<void *> result;
            result.reserve(functions->length());
            for (int i = functions->length() - 1; i >= 0; i--) {
                auto addr = functions->nth(i);
                if (!skip_public_code || !is_public_code(addr))
                    result.push_back(addr);
            }

            return result;
        }
    };// namespace SymbolUtil
    struct MemoryRange {
        void *base_address;
        size_t size;

        bool contains(void *addr) const noexcept {
            return addr >= base_address && addr <= (void *) ((intptr_t) base_address + size);
        }
    };

    struct ModuleDetails {
        virtual ~ModuleDetails() = default;
        virtual const char *name() const = 0;
        virtual MemoryRange range() const = 0;
        virtual const char *path() const = 0;
    };

    using FoundModuleFunc = std::function<bool(const ModuleDetails &details)>;
    enum class ExportType {
        FUNCTION = 1,
        VARIABLE
    };
    struct ExportDetails {
        ExportType type;
        const char *name;
        void *address;
    };
    enum class ImportType {
        UNKNOWN,
        FUNCTION,
        VARIABLE,
    };
    struct ImportDetails {
        ImportType type;
        const char *name;
        const char *module;
        void *address;
        void **slot;
    };
    enum PageProtection {
        NO_ACCESS = 0,
        READ = (1 << 0),
        WRITE = (1 << 1),
        EXECUTE = (1 << 2),
    };
    struct SymbolSection {
        const char *id;
        PageProtection protection;
    };

    enum SymbolType {
        /* Common */
        UNKNOWN,
        SECTION,

        /* Mach-O */
        UNDEFINED,
        ABSOLUTE,
        PREBOUND_UNDEFINED,
        INDIRECT,

        /* ELF */
        OBJECT,
        FUNCTION,
        FILE,
        COMMON,
        TLS,
    };

    struct SymbolDetails {
        bool is_global;
        SymbolType type;
        const SymbolSection *section;
        const char *name;
        void *address;
        ssize_t size;
    };
    using ProcessId = uint32_t;
    using ThreadId = size_t;
    namespace Process {
        void enumerate_modules(const FoundModuleFunc &func);
        bool module_load(const char *name, std::string *error);
        void *module_find_symbol_by_name(const char *module_name, const char *symbol_name);
        void *module_find_export_by_name(const char *module_name, const char *symbol_name);
        void module_enumerate_export(const char *module_name, const std::function<bool(const ExportDetails &details)> &callback);
        void module_enumerate_import(const char *module_name, const std::function<bool(const ImportDetails &details)> &callback);
        void module_enumerate_symbols(const char *module_name, const std::function<bool(const SymbolDetails &details)> &callback);
        ProcessId get_id();
        ThreadId get_current_thread_id();
    }// namespace Process

    void runtime_init();
    void runtime_deinit();

    struct signature {
        std::string pattern;
        int8_t offset;
    };

    signature get_function_signature(void *start_address, int limit);
    std::vector<void *> search_module_function(const char *module_name, const char *pattern);
    std::vector<const char *> search_module_string(const char *module_name, const char *str);
}// namespace Gum

#endif
