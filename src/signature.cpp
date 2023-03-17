#include <frida-gum.h>

#include <string>
#include <vector>
#if defined(_M_ARM64) || defined(__aarch64__)
#define GUMPP_ARCH_ARM64 1
#elif defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
#define GUMPP_ARCH_X86 1
#else
#error "Unsupported architecture"
#endif

#include "signature/arm64.hpp"
#include "signature/x86.hpp"

#include <gumpp.hpp>

namespace Gum {

    signature get_function_signature(void *start_address, size_t limit) {
        auto pattern =
#ifdef GUMPP_ARCH_ARM64
                to_arm64_signature_pattern(start_address, limit);
#elif GUMPP_ARCH_X86
                to_x86_signature_pattern(start_address, limit);
#endif
        int8_t offset = 0;
        auto size = pattern.size();
        while (size >= 2 && pattern[size - 1] == '?' && pattern[size - 2] == '?') {
            pattern.pop_back();
            pattern.pop_back();
            size = pattern.size();
        }

        while (size >= 2 && pattern[0] == '?' && pattern[1] == '?') {
            pattern.erase(pattern.begin());
            pattern.erase(pattern.begin());
            size = pattern.size();
            offset--;// TODO: big endian or little endian
        }
        return {pattern, offset};
    }

    static std::vector<void *> search_module_signature_code(const char *module_name, GumPageProtection prot, GumMatchPattern *pattern) {
        struct search_signed_code_in_module_ctx {
            GumMatchPattern *pattern;
            std::vector<void *> find_address;
        } ctx{pattern};

        gum_module_enumerate_ranges(
                module_name, prot,
                [](const GumRangeDetails *details, gpointer user_data) -> gboolean {
                    auto ctx = (search_signed_code_in_module_ctx *) user_data;
                    gum_memory_scan(
                            details->range, ctx->pattern,
                            [](GumAddress address, gsize size, gpointer user_data) -> gboolean {
                                auto ctx = (search_signed_code_in_module_ctx *) user_data;
                                ctx->find_address.push_back(GSIZE_TO_POINTER(address));
                                return true;
                            },
                            user_data);
                    return true;
                },
                (void *) &ctx);

        return std::move(ctx.find_address);
    }

    std::vector<const char *> search_module_string(const char *module_name, const char *str) {
        std::string pattern;
        for (size_t i = 0; i < strlen(str); i++) {
            char res[3] = {};
            snprintf(res, 3, "%02x", str[i]);
            pattern.append(res, 2);
        }

        auto match_pattern = gum_match_pattern_new_from_string(pattern.c_str());
        if (!match_pattern) return {};
        auto result =
                search_module_signature_code(module_name, GUM_PAGE_READ, match_pattern);
        gum_match_pattern_unref(match_pattern);
        std::vector<const char *> res;
        res.reserve(result.size());
        for (auto addr: result) {
            res.push_back((const char *) addr);
        }
        return res;
    }

    std::vector<void *> search_module_function(const char *module_name, const char *pattern) {
        auto match_pattern = gum_match_pattern_new_from_string(pattern);
        if (!match_pattern) return {};
        auto result = search_module_signature_code(
                module_name, GUM_PAGE_EXECUTE | GUM_PAGE_READ, match_pattern);
        gum_match_pattern_unref(match_pattern);
        return result;
    }
}// namespace Gum