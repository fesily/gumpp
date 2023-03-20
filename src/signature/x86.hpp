#pragma once
#include "private_common.hpp"

#include "../internal/arch-x86/gumx86reader.h"
#include "../internal/arch-x86/gumx86relocator.h"

namespace Gum {
    SIGNATURE_HANDLER_(x86)

    std::string signature_handler_x86::_signature_relocator(const cs_insn *insn) {
        const auto &x86_insn = insn->detail->x86;
        switch (insn->id) {
            case X86_INS_CALL:
            case X86_INS_JMP:
                break;
            case X86_INS_JECXZ:
            case X86_INS_JRCXZ:
                break;
            case X86_INS_SYSCALL:
                //ONLY ON LINUX and x86
                break;
            case X86_INS_JA:
            case X86_INS_JAE:
            case X86_INS_JB:
            case X86_INS_JBE:
            case X86_INS_JE:
            case X86_INS_JG:
            case X86_INS_JGE:
            case X86_INS_JL:
            case X86_INS_JLE:
            case X86_INS_JNE:
            case X86_INS_JNO:
            case X86_INS_JNP:
            case X86_INS_JNS:
            case X86_INS_JO:
            case X86_INS_JP:
            case X86_INS_JS:
                break;
            default: {
                if (x86_insn.encoding.modrm_offset == 0) {
                    return to_hex((void *) insn->bytes, insn->size);
                }
                guint mod = (x86_insn.modrm & 0xc0) >> 6;
                guint rm = (x86_insn.modrm & 0x07) >> 0;
                gboolean is_rip_relative = (mod == 0 && rm == 5);
                if (!is_rip_relative)
                    return to_hex((void *) insn->bytes, insn->size);
                break;
            }
        }
        return std::string(insn->size * 2, '?');
    }
}// namespace Gum