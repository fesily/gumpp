#include "private_common.hpp"

#include "../internal/arch-x86/gumx86reader.h"
#include "../internal/arch-x86/gumx86relocator.h"

namespace Gum {
SIGNATURE_HANDLER_(x86)

std::string to_signature_code(void* start_address, size_t limit) {
    return signature_handler_x86{}.to_signature_code(start_address, limit);
}
}