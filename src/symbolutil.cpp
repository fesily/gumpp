#include "gumpp.hpp"

#include "podwrapper.hpp"
#include "runtime.hpp"

#include <frida-gum.h>
#include "string.hpp"

#include <memory>

namespace Gum {
    class SymbolPtrArray : public PodWrapper<SymbolPtrArray, PtrArray, GArray> {
    public:
        SymbolPtrArray(GArray *arr) { assign_handle(arr); }

        virtual ~SymbolPtrArray() {
            g_array_free(handle, TRUE);

            Runtime::unref();
        }

        virtual int length() { return handle->len; }

        virtual void *nth(int n) { return g_array_index(handle, gpointer, n); }
    };

    RefPtr<PtrArray> find_matching_functions_array(const char *str) {
        Runtime::ref();
        return {new SymbolPtrArray(gum_find_functions_matching(str))};
    }

    RefPtr<String> get_function_name_from_addr(void *addr) {
        Runtime::ref();
        gchar *name = gum_symbol_name_from_address(addr);
        Runtime::unref();
        return {new StringImpl(name)};
    }

    struct DebugSymbolDetailsImpl : DebugSymbolDetails {
        GumDebugSymbolDetails details;
        virtual ~DebugSymbolDetailsImpl() = default;
        virtual void *address() const { return GSIZE_TO_POINTER(details.address); }
        virtual const char *module_name() const { return details.module_name; }
        virtual const char *symbol_name() const { return details.symbol_name; }
        virtual const char *file_name() const { return details.file_name; }
        virtual uint32_t line_number() const { return details.line_number; }
        virtual uint32_t column() const { return details.column; }
    };// namespace Gum
    namespace SymbolUtil {
        std::unique_ptr<DebugSymbolDetails> details_from_address(void *addr) {
            auto impl = std::make_unique<DebugSymbolDetailsImpl>();
            if (!gum_symbol_details_from_address(addr, &impl->details)) {
                return nullptr;
            }
            return impl;
        }

        void *find_function(const char *name) {
            Runtime::ref();
            void *result = gum_find_function(name);
            Runtime::unref();
            return result;
        }

        std::optional<MemoryRange> function_range_from_address(void *addr) {
            GumDebugSymbolDetails details;
            if (!gum_symbol_details_from_address(addr, &details)) {
                return std::nullopt;
            }
            constexpr auto max_body_size = 4096;
            struct function_range_from_address_ctx {
                GumAddress address;
                GumAddress next_symbol;
            } ctx = {details.address, details.address + max_body_size};
            gum_module_enumerate_symbols(
                    details.module_name, [](const GumSymbolDetails *symbol, gpointer user_data) -> gboolean {
                        auto &ctx = *reinterpret_cast<function_range_from_address_ctx *>(user_data);
                        if (symbol->address > ctx.address && symbol->address - ctx.address < ctx.next_symbol - ctx.address) {
                            ctx.next_symbol = symbol->address;
                        }
                        return true;
                    },
                    (void *) &ctx);
            return MemoryRange{GSIZE_TO_POINTER(ctx.address), size_t(ctx.next_symbol - ctx.address)};
        }

        void *find_function_end(void *addr, size_t max_size) {
            csh capstone;
            if (cs_open(GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone) != CS_ERR_OK)
                return nullptr;
            auto insn = cs_malloc(capstone);
            auto _ = std::unique_ptr<void, std::function<void(void *)>>(nullptr, [&](auto) {
                if (capstone)
                    cs_close(&capstone);
                if (insn)
                    cs_free(insn, 1);
            });
            if (insn == nullptr) {
                return nullptr;
            }
            auto buf = std::make_unique<uint8_t[]>(max_size);
            std::memcpy(buf.get(), addr, max_size);
            const uint8_t *code = buf.get();
            size_t size = max_size;
            auto start = GPOINTER_TO_SIZE(addr);
            uint64_t address = start & ~G_GUINT64_CONSTANT(1);

            GumAddress match = 0;
            switch (GUM_DEFAULT_CS_ARCH) {
                case CS_ARCH_X86:
                    while (cs_disasm_iter(capstone, &code, &size, &address, insn)) {
                        if (insn->id == X86_INS_RET ||
                            insn->id == X86_INS_RETF ||
                            insn->id == X86_INS_RETFQ) {
                            match = insn->address;
                            break;
                        }
                    }
                    break;
                case CS_ARCH_ARM: {
                    int i, pop_lr = -1;

                    while (cs_disasm_iter(capstone, &code, &size, &address, insn)) {
                        if (insn->id == ARM_INS_PUSH &&
                            insn->address == (start & ~1)) {
                            for (i = 0; i != insn->detail->arm.op_count; i++) {
                                if (insn->detail->arm.operands[i].reg == ARM_REG_LR) {
                                    pop_lr = i;
                                    break;
                                }
                            }
                        }

                        if ((insn->id == ARM_INS_BX || insn->id == ARM_INS_BXJ) &&
                            insn->detail->arm.operands[0].type == ARM_OP_REG &&
                            insn->detail->arm.operands[0].reg == ARM_REG_LR) {
                            match = insn->address;
                            break;
                        }

                        if (insn->id == ARM_INS_POP &&
                            pop_lr >= 0 &&
                            pop_lr < insn->detail->arm.op_count) {
                            if (insn->detail->arm.operands[pop_lr].reg == ARM_REG_PC) {
                                match = insn->address;
                                break;
                            }
                        }
                    }

                    break;
                }

                case CS_ARCH_ARM64:
                    while (cs_disasm_iter(capstone, &code, &size, &address, insn)) {
                        if (insn->id == ARM64_INS_RET) {
                            match = insn->address;
                            break;
                        }
                    }
                    break;

                default:
                    g_assert_not_reached();
            }
            if (!match) {
                return nullptr;
            }
            return GSIZE_TO_POINTER((uint8_t *) match + insn->size);
        }
    }// namespace SymbolUtil
}// namespace Gum