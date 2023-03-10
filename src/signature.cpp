#include <frida-gum.h>

#include <string>
#include <vector>
#if defined (_M_ARM64) || defined (__aarch64__)
#define GUMPP_ARCH_ARM64 1
#elif defined (_M_X64) || defined (__x86_64__)
#define GUMPP_ARCH_X86 1
#else
#error "Unsupported architecture"
#endif

#include "signature/arm64.hpp"
#include "signature/x86.hpp"

namespace Gum {

    std::string to_signature_code(void* start_address, size_t limit) {
#ifdef GUMPP_ARCH_ARM64
        return to_arm64_signature_code(start_address, limit);
#elif GUMPP_ARCH_X86
        return to_x86_signature_code(start_address, limit);
#endif
    }

    static std::vector<void*> search_module_signature_code(const char* module_name,
                                                           GumPageProtection prot,
                                                           GumMatchPattern* pattern) {
        struct search_signed_code_in_module_ctx {
            GumMatchPattern* pattern;
            std::vector<void*> find_address;
        } ctx{pattern};

        gum_module_enumerate_ranges(
                module_name, prot,
                [](const GumRangeDetails* details, gpointer user_data) -> gboolean {
                    auto ctx = (search_signed_code_in_module_ctx*) user_data;
                    gum_memory_scan(
                            details->range, ctx->pattern,
                            [](GumAddress address, gsize size, gpointer user_data) -> gboolean {
                                auto ctx = (search_signed_code_in_module_ctx*) user_data;
                                ctx->find_address.push_back(GSIZE_TO_POINTER(address));
                                return true;
                            },
                            user_data);
                    return true;
                },
                (void*) &ctx);

        return std::move(ctx.find_address);
    }

    std::vector<void*> search_module_string(const char* module_name,
                                            const char* str) {
        std::string pattern;
        for (size_t i = 0; i < strlen(str); i++) {
            char res[3] = {};
            snprintf(res, 3, "%02x", str[i]);
            pattern.append(res, 2);
        }
        pattern += "00";
        auto match_pattern = gum_match_pattern_new_from_string(pattern.c_str());
        auto result =
                search_module_signature_code(module_name, GUM_PAGE_READ, match_pattern);
        gum_match_pattern_unref(match_pattern);
        return result;
    }

    std::vector<void*> search_module_function(const char* module_name,
                                              const char* pattern) {
        auto match_pattern = gum_match_pattern_new_from_string(pattern);
        auto result = search_module_signature_code(
                module_name, GUM_PAGE_EXECUTE | GUM_PAGE_READ, match_pattern);
        gum_match_pattern_unref(match_pattern);
        return result;
    }
}