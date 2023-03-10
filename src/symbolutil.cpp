#include "gumpp.hpp"

#include "podwrapper.hpp"
#include "runtime.hpp"

#include <frida-gum.h>
#include "string.hpp"

namespace Gum {
class SymbolPtrArray : public PodWrapper<SymbolPtrArray, PtrArray, GArray> {
 public:
  SymbolPtrArray(GArray* arr) { assign_handle(arr); }

  virtual ~SymbolPtrArray() {
    g_array_free(handle, TRUE);

    Runtime::unref();
  }

  virtual int length() { return handle->len; }

  virtual void* nth(int n) { return g_array_index(handle, gpointer, n); }
};

void* find_function_ptr(const char* name) {
  Runtime::ref();
  void* result = gum_find_function(name);
  Runtime::unref();
  return result;
}
RefPtr<PtrArray> find_matching_functions_array(const char* str) {
  Runtime::ref();
  return {new SymbolPtrArray(gum_find_functions_matching(str))};
}

RefPtr<String> get_function_name_from_addr(void* addr) {
  Runtime::ref();
  gchar* name = gum_symbol_name_from_address(addr);
  Runtime::unref();
  return {new StringImpl(name)};
}

struct DebugSymbolDetailsImpl : DebugSymbolDetails {
  GumDebugSymbolDetails details;
  virtual ~DebugSymbolDetailsImpl() = default;
  virtual void* address() const { return GSIZE_TO_POINTER(details.address); }
  virtual const char* module_name() const { return details.module_name; }
  virtual const char* symbol_name() const { return details.symbol_name; }
  virtual const char* file_name() const { return details.file_name; }
  virtual uint32_t line_number() const { return details.line_number; }
  virtual uint32_t column() const { return details.column; }
};  // namespace Gum

std::unique_ptr<DebugSymbolDetails> SymbolUtil::details_from_address(void* addr) {
  auto impl = std::make_unique<DebugSymbolDetailsImpl>();
  if (!gum_symbol_details_from_address(addr, &impl->details)) {
    return nullptr;
  }
  return impl;
}
}  // namespace Gum