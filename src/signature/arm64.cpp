#include "private_common.hpp"

#include "../internal/arch-arm64/gumarm64reader.h"
#include "../internal/arch-arm64/gumarm64relocator.h"
namespace Gum {
    SIGNATURE_HANDLER_(arm64)

    template<typename Func>
    size_t signature_handler_arm64::_inst_length(Func &&fn, gpointer address) {
        return sizeof(uint32_t);
    }

    std::string signature_handler_arm64::_signature_relocator(gpointer, size_t) {
        return std::string(sizeof(uint32_t), 'f');
    }

    std::string to_signature_code(void *start_address, size_t limit) {
        return signature_handler_arm64{}.to_signature_code(start_address, limit);
    }
}// namespace Gum