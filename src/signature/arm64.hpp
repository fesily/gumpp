#pragma once
#ifdef GUMPP_ARCH_ARM64
#include "private_common.hpp"

#include "../internal/arch-arm64/gumarm64reader.h"
#include "../internal/arch-arm64/gumarm64relocator.h"
namespace Gum {
    SIGNATURE_HANDLER_(arm64)

    std::string signature_handler_arm64::_signature_relocator(const cs_insn *insn) {
        auto &arm64_insn = insn->detail->arm64;
        switch (insn->id) {
            case ARM64_INS_LDR:
            case ARM64_INS_LDRSW: {
                //auto dst = arm64_insn.operands[0];
                auto src = arm64_insn.operands[1];
                if (src.type != ARM64_OP_IMM) {
                    return to_hex((void *) insn->bytes, insn->size);
                }
                break;
            }
            case ARM64_INS_ADR:
            case ARM64_INS_ADRP:
            case ARM64_INS_B:
                if (arm64_insn.operands[0].type == ARM64_OP_IMM && in_function((void *) arm64_insn.operands[0].imm)) {
                    return to_hex((void *) insn->bytes, insn->size);
                }
                break;
            case ARM64_INS_BL:
                return "??????9?";
            case ARM64_INS_CBZ:
            case ARM64_INS_CBNZ:
            case ARM64_INS_TBZ:
            case ARM64_INS_TBNZ:
                return to_hex((void *) insn->bytes, insn->size);
            default:
                break;
        }
        return std::string(insn->size * 2, '?');
    }

}// namespace Gum
#endif