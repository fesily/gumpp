#pragma once

#include <frida-gum.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace Gum {
    using insn_ptr_t = std::unique_ptr<cs_insn, void (*)(cs_insn *)>;

    inline std::string to_hex(uint8_t b) {
        char res[3] = {};
        snprintf(res, 3, "%02x", b);
        return res;
    }

    template<typename T>
    struct signature_handler {
        static insn_ptr_t instruction_at(gpointer address) {
            return {T::gum_reader_disassemble_instruction_at((gconstpointer) address),
                    [](cs_insn *inst) { cs_free(inst, 1); }};
        }

        static size_t inst_length(gpointer address) {
            return T::_inst_length(instruction_at, address);
        }

        static std::string signature_relocator(gpointer address, size_t inst_length) {
            return T::_signature_relocator(address, inst_length);
        }

        template<typename Relocator>
        static void read_inst(Relocator relocator, size_t limit) {
            while (true) {
                T::gum_relocator_read_one(relocator, nullptr);
                if (T::gum_relocator_eob(relocator) && T::gum_relocator_eoi(relocator)) {
                    break;
                }
                if (--limit <= 0)
                    break;
            }
        }

        static std::string to_signature_code(void *start_address, size_t limit) {
            using inst_t = uint32_t;
            const auto code_address = gum_malloc(limit);
            memset(code_address, 0, limit);
            const auto writer = T::gum_writer_new(code_address);
            const auto relocator = T::gum_relocator_new(start_address, writer);

            read_inst(relocator, limit);

            std::string output;
            guint count = 0;
            guint offset = T::gum_writer_offset(writer);
            gpointer pc = T::gum_writer_cur(writer);
            auto old_address = (inst_t *) start_address;
            while (T::gum_relocator_write_one(relocator)) {
                auto target_address = (inst_t *) pc;
                guint new_offset = T::gum_writer_offset(writer);
                gpointer new_pc = T::gum_writer_cur(writer);
                auto old_inst_length = inst_length(old_address);
                if (new_offset - offset != old_inst_length) {
                    // 说明这个指令重写为多条,直接使用??????替换掉
                    // TODO:应该提取这个指令的固定部分,但是需要按半个字节固定才行
                    output.append(signature_relocator(old_address, old_inst_length));
                } else {
                    // 这个指令有没有重写为多条, 判断是不是重写过指令
                    if (memcmp(old_address, target_address, old_inst_length) != 0) {
                        auto old_inst = instruction_at((inst_t *) old_address);
                        auto new_inst = instruction_at((inst_t *) target_address);
                        g_assert_cmpuint(old_inst->size, ==, new_inst->size);

                        for (size_t i = 0; i < old_inst->size; i++) {
                            if (old_inst->bytes[i] == new_inst->bytes[i]) {
                                output.append(to_hex(old_inst->bytes[i]));
                            } else {
                                if ((old_inst->bytes[i] & 0xf0) == (new_inst->bytes[i] & 0xf0))
                                    output += to_hex(old_inst->bytes[i] & 0xf0);
                                else
                                    output += '?';
                                if ((old_inst->bytes[i] & 0x0f) == (new_inst->bytes[i] & 0x0f))
                                    output += to_hex(old_inst->bytes[i] & 0x0f);
                                else
                                    output += '?';
                            }
                        }
                    } else {
                        for (int i = 0; i < old_inst_length; ++i) {
                            const auto b = ((uint8_t *) old_address)[i];
                            output.append(to_hex(b));
                        }
                    }
                }
                pc = new_pc;
                offset = new_offset;
                old_address = (inst_t *) ((uintptr_t) old_address + old_inst_length);
                count++;
            }
            g_assert(count > 0);
            g_assert(output.size() % 2 == 0);
            gum_free(code_address);
            return output;
        }
    };

#define SIGNATURE_HANDLER_(arch) \
class signature_handler_##arch\
    : public signature_handler<signature_handler_##arch> {\
  friend struct signature_handler<signature_handler_##arch>;\
  static constexpr auto& gum_writer_new = gum_##arch##_writer_new;\
  static constexpr auto& gum_relocator_new = gum_##arch##_relocator_new;\
  static constexpr auto& gum_relocator_read_one = gum_##arch##_relocator_read_one;\
  static constexpr auto& gum_relocator_eob = gum_##arch##_relocator_eob;\
  static constexpr auto& gum_relocator_eoi = gum_##arch##_relocator_eoi;\
  static constexpr auto& gum_writer_offset = gum_##arch##_writer_offset;\
  static constexpr auto& gum_writer_cur = gum_##arch##_writer_cur;\
  static constexpr auto& gum_relocator_write_one =\
      gum_##arch##_relocator_write_one;\
  static constexpr auto& gum_reader_disassemble_instruction_at =\
      gum_##arch##_reader_disassemble_instruction_at;\
  template<typename Func>\
  static size_t _inst_length(Func&& fn, gpointer address);\
  static std::string _signature_relocator(gpointer address, size_t inst_length);\
};
}