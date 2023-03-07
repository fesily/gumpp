#include "private_common.hpp"

#include "../internal/arch-arm64/gumarm64reader.h"
#include "../internal/arch-arm64/gumarm64relocator.h"
namespace Gum {
SIGNATURE_HANDLER_(arm64)

std::string to_signature_code(void* start_address, size_t limit) {
    return signature_handler_arm64{}.to_signature_code(start_address, limit);
}
}