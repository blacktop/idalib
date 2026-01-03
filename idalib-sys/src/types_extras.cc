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

bool idalib_declare_type(const char *decl, bool relaxed, bool replace, type_decl_result &out) {
  tinfo_t tif;
  qstring name;
  int pt_flags = PT_TYP | PT_SIL | PT_SEMICOLON;
  if (relaxed) {
    pt_flags |= PT_RELAXED;
  }
  if (!parse_decl(&tif, &name, nullptr, decl, pt_flags)) {
    out.code = TERR_BAD_TYPE;
    return false;
  }

  if (name.empty()) {
    out.code = TERR_BAD_NAME;
    return false;
  }

  int ntf_flags = NTF_COPY;
  if (replace) {
    ntf_flags |= NTF_REPLACE;
  }
  tinfo_code_t code = tif.set_named_type(nullptr, name.c_str(), ntf_flags);
  out.code = code;
  out.name = rust::String(name.c_str());
  const char *decl_str = tif.dstr();
  out.decl = decl_str ? rust::String(decl_str) : rust::String();
  out.kind = kind_from_tinfo(tif);
  return code == TERR_OK;
}

int idalib_declare_types(const char *decls, bool relaxed) {
  int flags = HTI_HIGH;
  if (relaxed) {
    flags |= HTI_RELAXED;
  }
  return parse_decls(nullptr, decls, nullptr, flags);
}

bool idalib_apply_decl_type(uint64_t ea, const char *decl, bool relaxed, bool delay, bool strict) {
  tinfo_t tif;
  qstring name;
  int pt_flags = PT_TYP | PT_SIL | PT_SEMICOLON;
  if (relaxed) {
    pt_flags |= PT_RELAXED;
  }
  if (!parse_decl(&tif, &name, nullptr, decl, pt_flags)) {
    return false;
  }

  uint32 flags = TINFO_DEFINITE;
  if (delay) {
    flags |= TINFO_DELAYFUNC;
  }
  if (strict) {
    flags |= TINFO_STRICT;
  }
  return apply_tinfo(static_cast<ea_t>(ea), tif, flags);
}

bool idalib_apply_named_type(uint64_t ea, const char *name) {
  return apply_named_type(static_cast<ea_t>(ea), name);
}

bool idalib_guess_tinfo(uint64_t id, type_guess_result &out) {
  tinfo_t tif;
  int code = guess_tinfo(&tif, static_cast<tid_t>(id));
  out.code = code;
  const char *decl = tif.dstr();
  out.decl = decl ? rust::String(decl) : rust::String();
  out.kind = kind_from_tinfo(tif);
  return true;
}
