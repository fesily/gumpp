#pragma once

#include <frida-gum.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <gumpp.hpp>

namespace Gum {
    using insn_ptr_t = std::unique_ptr<cs_insn, void (*)(cs_insn *)>;

    inline std::string to_hex(uint8_t b) {
        char res[3] = {};
        snprintf(res, 3, "%02x", b);
        return res;
    }

    inline std::string to_hex(void *address, size_t inst_length) {
        std::string output;
        for (int i = 0; i < inst_length; ++i) {
            const auto b = ((uint8_t *) address)[i];
            output.append(to_hex(b));
        }
        return output;
    }

    template<typename T>
    struct signature_handler {
        MemoryRange range;
        static insn_ptr_t instruction_at(gpointer address) {
            return {T::gum_reader_disassemble_instruction_at((gconstpointer) address),
                    [](cs_insn *inst) { cs_free(inst, 1); }};
        }

        T &get_self() {
            return *static_cast<T *>(this);
        }

        std::string signature_relocator(const insn_ptr_t &insn) {
            return get_self()._signature_relocator(insn.get());
        }
        template<class relocator_t>
        size_t read_inst(relocator_t relocator, size_t limit) {
            while (true) {
                T::gum_relocator_read_one(relocator, nullptr);
                if (T::gum_relocator_eob(relocator) && T::gum_relocator_eoi(relocator)) {
                    break;
                }
                if (--limit <= 0)
                    break;
            }
            return limit;
        }

        std::string to_signature_pattern_impl(void *start_address, size_t limit, void **end_address, size_t *scaned_insn_count) {
            using inst_t = uint32_t;
            limit = limit > 100 ? 100 : limit;
            g_assert_cmpuint(limit * 16, <, 4096);
            const auto code_address = gum_malloc(4096);
            memset(code_address, 0, 4096);
            const auto writer = T::gum_writer_new(code_address);
            const auto relocator = T::gum_relocator_new(start_address, writer);

            *scaned_insn_count = limit - read_inst(relocator, limit);

            std::string output;
            guint count = 0;
            guint offset = T::gum_writer_offset(writer);
            gpointer pc = T::gum_writer_cur(writer);
            auto old_address = (inst_t *) start_address;
            auto old_inst = instruction_at((inst_t *) old_address);

            while (T::gum_relocator_write_one(relocator)) {
                auto target_address = (inst_t *) pc;
                guint new_offset = T::gum_writer_offset(writer);
                gpointer new_pc = T::gum_writer_cur(writer);
                auto old_inst_length = old_inst->size;
                if (new_offset - offset != old_inst_length) {
                    // 说明这个指令重写为多条,直接使用??????替换掉
                    // TODO:应该提取这个指令的固定部分,但是需要按半个字节固定才行
                    output.append(signature_relocator(old_inst));
                } else {
                    // 这个指令有没有重写为多条, 判断是不是重写过指令
                    if (memcmp(old_address, target_address, old_inst_length) != 0) {
                        auto new_inst = instruction_at((inst_t *) target_address);
                        g_assert_cmpuint(old_inst->size, ==, new_inst->size);

                        for (size_t i = 0; i < old_inst->size; i++) {
                            if (old_inst->bytes[i] == new_inst->bytes[i]) {
                                output.append(to_hex(old_inst->bytes[i]));
                            } else {
                                if ((old_inst->bytes[i] & 0xf0) == (new_inst->bytes[i] & 0xf0))
                                    output += to_hex(old_inst->bytes[i] & 0xf0).at(0);
                                else
                                    output += '?';
                                if ((old_inst->bytes[i] & 0x0f) == (new_inst->bytes[i] & 0x0f))
                                    output += to_hex(old_inst->bytes[i] & 0x0f).at(1);
                                else
                                    output += '?';
                            }
                        }
                    } else {
                        output += to_hex(old_address, old_inst_length);
                    }
                }
                pc = new_pc;
                offset = new_offset;
                old_address = (inst_t *) ((uintptr_t) old_address + old_inst_length);
                old_inst = instruction_at((inst_t *) old_address);
                count++;
            }
            g_assert(count > 0);
            g_assert(output.size() % 2 == 0);
            T::gum_relocator_unref(relocator);
            T::gum_writer_unref(writer);
            gum_free(code_address);
            *end_address = old_address;
            return output;
        }

        std::string to_signature_pattern(void *start_address, int limit) {
            void *end_address = 0;
            size_t scaned_insn_count = 0;
            auto pattern = to_signature_pattern_impl(start_address, limit, &end_address, &scaned_insn_count);
            auto insn = instruction_at(end_address);
            auto left = limit - scaned_insn_count;
            if (scaned_insn_count != 0 && left >= 1 && in_function((void *) insn->address))
                return pattern + to_signature_pattern(end_address, left);
            return pattern;
        }

        bool in_function(void *address) const {
            return range.contains(address);
        }
    };

#define SIGNATURE_HANDLER_(arch)                                                         \
    struct signature_handler_##arch                                                      \
        : signature_handler<signature_handler_##arch> {                                  \
        static constexpr auto &gum_writer_new = gum_##arch##_writer_new;                 \
        static constexpr auto &gum_relocator_new = gum_##arch##_relocator_new;           \
        static constexpr auto &gum_relocator_read_one = gum_##arch##_relocator_read_one; \
        static constexpr auto &gum_relocator_eob = gum_##arch##_relocator_eob;           \
        static constexpr auto &gum_relocator_eoi = gum_##arch##_relocator_eoi;           \
        static constexpr auto &gum_writer_offset = gum_##arch##_writer_offset;           \
        static constexpr auto &gum_writer_cur = gum_##arch##_writer_cur;                 \
        static constexpr auto &gum_relocator_write_one =                                 \
                gum_##arch##_relocator_write_one;                                        \
        static constexpr auto &gum_reader_disassemble_instruction_at =                   \
                gum_##arch##_reader_disassemble_instruction_at;                          \
        static constexpr auto &gum_relocator_unref =                                     \
                gum_##arch##_relocator_unref;                                            \
        static constexpr auto &gum_writer_unref =                                        \
                gum_##arch##_writer_unref;                                               \
        std::string _signature_relocator(const cs_insn *insn);                           \
    };
}// namespace Gum