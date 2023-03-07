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
using insn_ptr_t = std::unique_ptr<cs_insn, void (*)(cs_insn*)>;

inline std::string to_hex(uint8_t b) {
  char res[3] = {};
  snprintf(res, 3, "%02x", b);
  return res;
}

template <typename inst_t>
constexpr std::array<char, sizeof(inst_t) * 2 + 1> inst_all_regex() {
  std::array<char, sizeof(inst_t)* 2 + 1> res = {};
  for (int i = 0; i < sizeof(inst_t) * 2; ++i) {
    res[i] = '?';
  }
  return res;
}

static_assert(inst_all_regex<uint32_t>().data() ==
              std::string_view("????????"));

template <typename T>
struct signature_handler {
  insn_ptr_t instruction_at(gpointer address) {
    return {T::gum_reader_disassemble_instruction_at((gconstpointer)address),
            [](cs_insn* inst) { cs_free(inst, 1); }};
  }
  std::string to_signature_code(void* start_address, size_t limit) {
    using inst_t = uint32_t;
    const auto code_address = gum_malloc(limit);
    memset(code_address, 0, limit);
    const auto writer = T::gum_writer_new(code_address);
    const auto relocator = T::gum_relocator_new(start_address, writer);
    guint read_offset = 0;
    while (true) {
      read_offset = T::gum_relocator_read_one(relocator, nullptr);
      read_offset /= sizeof(inst_t);
      if (T::gum_relocator_eob(relocator) && T::gum_relocator_eoi(relocator)) {
        break;
      }
      if (read_offset >= limit)
        break;
    }
    std::string output;
    output.reserve(sizeof(inst_t) * 2 * (limit + 1));
    guint count = 0;
    guint offset = T::gum_writer_offset(writer);
    gpointer pc = T::gum_writer_cur(writer);
    while (T::gum_relocator_write_one(relocator)) {
      guint new_offset = T::gum_writer_offset(writer);
      gpointer new_pc = T::gum_writer_cur(writer);
      if (new_offset - offset != sizeof(inst_t)) {
        // 说明这个指令重写为多条,直接使用??????替换掉
        // TODO:应该提取这个指令的固定部分,但是需要按半个字节固定才行
        output.append(inst_all_regex<inst_t>().data());
      } else {
        // 这个指令有没有重写为多条, 判断是不是重写过指令
        auto target_address = (inst_t*)pc;
        auto* ptr =
            (inst_t*)((uintptr_t)start_address + count * sizeof(inst_t));
        if (memcmp(ptr, target_address, sizeof(inst_t)) != 0) {
          auto old_inst = instruction_at((inst_t*)ptr);
          auto new_inst = instruction_at((inst_t*)target_address);
          g_assert_cmpuint(old_inst->size, ==, new_inst->size);

          for (size_t i = 0; i < old_inst->size; i++) {
            if (old_inst->bytes[i] == new_inst->bytes[i]) {
              output.append(to_hex(old_inst->bytes[i]));
            } else {
              output += "??";
            }
          }
        } else {
          for (auto b : *(std::array<uint8_t, 4>*)(ptr)) {
            output.append(to_hex(b));
          }
        }
      }
      pc = new_pc;
      offset = new_offset;
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
};
}