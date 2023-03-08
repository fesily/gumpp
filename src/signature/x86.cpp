#include "private_common.hpp"

#include "../internal/arch-x86/gumx86reader.h"
#include "../internal/arch-x86/gumx86relocator.h"

namespace Gum {
SIGNATURE_HANDLER_(x86)

template<typename Func>
size_t signature_handler_x86::inst_length(Func&& fn, gpointer address){
    return fn(address)->size;
}

std::string signature_handler_x86::signature_relocator(gpointer address, size_t inst_length){
    return std::string(inst_length, 'f');
}

std::string to_signature_code(void* start_address, size_t limit) {
    return signature_handler_x86{}.to_signature_code(start_address, limit);
}
}