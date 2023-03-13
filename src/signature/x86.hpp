#pragma once
#ifdef GUMPP_ARCH_X86
#include "private_common.hpp"

#include "../internal/arch-x86/gumx86reader.h"
#include "../internal/arch-x86/gumx86relocator.h"

namespace Gum {
    SIGNATURE_HANDLER_(x86)

    std::string signature_handler_x86::_signature_relocator(const cs_insn* insn) {
        return std::string(insn->size * 2, '?');
    }

    std::string to_x86_signature_pattern(void* start_address, size_t limit) {
        return Gum::signature_handler_x86{}.to_signature_pattern(start_address, limit);
    }
}
#endif