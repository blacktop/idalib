#include "cxxgen1.h"
#include "typeinf.hpp"

static rust::String kind_from_tinfo(const tinfo_t &tif) {
  if (tif.is_struct()) {
    return rust::String("struct");
  }
  if (tif.is_union()) {
    return rust::String("union");
  }
  if (tif.is_enum()) {
    return rust::String("enum");
  }
  if (tif.is_func()) {
    return rust::String("function");
  }
  if (tif.is_ptr()) {
    return rust::String("pointer");
  }
  if (tif.is_array()) {
    return rust::String("array");
  }
  if (tif.is_typedef()) {
    return rust::String("typedef");
  }
  return rust::String("other");
}

bool idalib_get_local_type(uint32 ordinal, local_type_info &out) {
  tinfo_t tif;
  if (!tif.get_numbered_type(nullptr, ordinal, BTF_TYPEDEF, true)) {
    return false;
  }

  const char *name = get_numbered_type_name(nullptr, ordinal);
  if (name == nullptr || name[0] == '\0') {
    return false;
  }
  out.name = rust::String(name);

  const char *decl = tif.dstr();
  out.decl = decl ? rust::String(decl) : rust::String();
  out.kind = kind_from_tinfo(tif);
  return true;
}
