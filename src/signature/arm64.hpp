#pragma once
#ifdef GUMPP_ARCH_ARM64
#include "private_common.hpp"

#include "../internal/arch-arm64/gumarm64reader.h"
#include "../internal/arch-arm64/gumarm64relocator.h"
namespace Gum {
    SIGNATURE_HANDLER_(arm64)

    std::string signature_handler_arm64::_signature_relocator(const cs_insn* insn) {
        return std::string(insn->size * 2, '?');
    }

    std::string to_arm64_signature_pattern(void* start_address, size_t limit) {
        return signature_handler_arm64{}.to_signature_pattern(start_address, limit);
    }

}// namespace Gum
#endif