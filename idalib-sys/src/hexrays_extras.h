#pragma once

#include "hexrays.hpp"
#include "lines.hpp"
#include "name.hpp"
#include "pro.h"

#include <cstdint>
#include <memory>
#include <sstream>
#include <stdexcept>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_hexrays_error_t
#define CXXBRIDGE1_STRUCT_hexrays_error_t
struct hexrays_error_t final {
  ::std::int32_t code;
  ::std::uint64_t addr;
  ::rust::String desc;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_error_t

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

// TODO(ida-9.5-hexrays-magic): remove the ...06 fallback below once the
// official IDA 9.5 SDK publishes hexrays.hpp with HEXRAYS_API_MAGIC ...06.
//
// The public releases/9.5 header still declares ...05, but the 9.5.261001
// runtime only accepts ...06, so init_hexrays_plugin() reports the decompiler
// as unavailable. Both sides were verified to share the same hx_* dispatch
// table (694/694 names and values), and calls go through get_hexdsp() without
// re-checking the magic, so accepting exactly ...06 at init is the only
// deviation. The static_assert fails the build as soon as the SDK submodule
// moves to a header that no longer declares ...05.
#if IDA_SDK_VERSION == 950
static_assert(HEXRAYS_API_MAGIC == 0x00DEC0DE00000005LL,
              "TODO(ida-9.5-hexrays-magic): the SDK's hexrays.hpp no longer "
              "declares HEXRAYS_API_MAGIC ...05, so the official IDA 9.5 SDK has "
              "landed. Delete the ...06 fallback in idalib_hexrays_init() "
              "(idalib-sys/src/hexrays_extras.h), remove the "
              "TODO(ida-9.5-hexrays-magic) notes, and rerun just test-decompile "
              "in ida-mcp-rs.");
inline constexpr int64 IDALIB_HEXRAYS_RUNTIME_MAGIC_95 = 0x00DEC0DE00000006LL;
#endif

inline bool idalib_hexrays_init() {
  if (init_hexrays_plugin(0)) {
    return true;
  }
#if IDA_SDK_VERSION == 950
  hexdsp_t *dummy = nullptr;
  return callui(ui_broadcast, IDALIB_HEXRAYS_RUNTIME_MAGIC_95, &dummy, 0).i ==
         (IDALIB_HEXRAYS_RUNTIME_MAGIC_95 >> 32);
#else
  return false;
#endif
}

inline cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

inline std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_func(func_t *f, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_func(f, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
}

inline rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

inline cblock_t *idalib_hexrays_cfunc_body(cfunc_t *f) {
  if (f == nullptr) {
    return nullptr;
  }
  return f->body.cblock;
}

inline std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

inline cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

inline std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }

// ============================================================================
// Eamap support - mapping addresses to decompiled statements
// ============================================================================

/// Opaque iterator for statements at an address
struct eamap_result {
  cinsnptrvec_t *vec;
  size_t index;

  eamap_result() : vec(nullptr), index(0) {}
  eamap_result(cinsnptrvec_t *v) : vec(v), index(0) {}
};

/// Check if the eamap is available (bounds computed)
inline bool idalib_hexrays_cfunc_has_eamap(cfunc_t *f) {
  return (f->statebits & CFS_BOUNDS) != 0;
}

/// Find statements at a specific address. Returns nullptr if not found.
inline std::unique_ptr<eamap_result> idalib_hexrays_cfunc_find_stmts_at(cfunc_t *f,
                                                                 ea_t addr) {
  eamap_t &em = f->get_eamap();
  auto it = eamap_find(&em, addr);
  if (it == eamap_end(&em)) {
    return nullptr;
  }
  return std::unique_ptr<eamap_result>(new eamap_result(&eamap_second(it)));
}

/// Get the number of statements at this address
inline std::size_t idalib_hexrays_eamap_result_len(const eamap_result &r) {
  return r.vec ? r.vec->size() : 0;
}

/// Get the next statement from the result, or nullptr if exhausted
inline cinsn_t *idalib_hexrays_eamap_result_next(eamap_result &r) {
  if (!r.vec || r.index >= r.vec->size()) {
    return nullptr;
  }
  return r.vec->at(r.index++);
}

/// Reset the iterator to the beginning
inline void idalib_hexrays_eamap_result_reset(eamap_result &r) { r.index = 0; }

/// Get the address (ea) of a cinsn_t
inline ea_t idalib_hexrays_cinsn_ea(const cinsn_t *insn) { return insn->ea; }

/// Get the opcode of a cinsn_t (cit_* constants)
inline int idalib_hexrays_cinsn_op(const cinsn_t *insn) { return insn->op; }

/// Print a single ctree item (cinsn_t or cexpr_t) as text
inline rust::String idalib_hexrays_citem_print(const citem_t *item,
                                        const cfunc_t *func) {
  qstring buf;
  // Use print1 to get the text representation
  item->print1(&buf, func);
  // Strip color codes
  qstring clean;
  tag_remove(&clean, buf);
  return rust::String(clean.c_str());
}

/// Print a statement with context (includes nested expressions)
inline rust::String idalib_hexrays_cinsn_print(const cinsn_t *insn,
                                        const cfunc_t *func) {
  return idalib_hexrays_citem_print(static_cast<const citem_t *>(insn), func);
}

// ============================================================================
// Boundaries support - mapping statements to address ranges
// ============================================================================

// addr_range is defined by cxx bridge, declare it here if not already defined
#ifndef CXXBRIDGE1_STRUCT_addr_range
#define CXXBRIDGE1_STRUCT_addr_range
struct addr_range final {
  ::std::uint64_t start;
  ::std::uint64_t end;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_addr_range

/// Get the address range covered by a statement. Returns false if not found.
inline bool idalib_hexrays_cfunc_get_stmt_bounds(cfunc_t *f, const cinsn_t *insn,
                                          addr_range *out) {
  boundaries_t &bounds = f->get_boundaries();
  auto it = boundaries_find(&bounds, insn);
  if (it == boundaries_end(&bounds)) {
    return false;
  }
  rangeset_t &rs = boundaries_second(it);
  if (rs.empty()) {
    return false;
  }
  // Return the first (usually only) range
  out->start = rs.begin()->start_ea;
  out->end = rs.begin()->end_ea;
  return true;
}

#ifndef CXXBRIDGE1_STRUCT_decompiler_lvar_info
#define CXXBRIDGE1_STRUCT_decompiler_lvar_info
struct decompiler_lvar_info final {
  ::rust::String name;
  ::rust::String type_name;
  ::rust::String location;
  ::rust::String locator;
  ::std::uint64_t definition_address;
  ::std::int32_t width;
  bool is_argument;
  bool has_user_name;
  bool has_user_type;
  using IsRelocatable = ::std::true_type;
};
#endif

inline lvars_t *idalib_hexrays_named_lvars(cfunc_t *f) {
  if (f == nullptr) {
    return nullptr;
  }
  // A fresh native decompilation has not necessarily assigned display names.
  f->get_pseudocode();
  return f->get_lvars();
}

inline size_t idalib_hexrays_lvar_count(cfunc_t *f) {
  const lvars_t *vars = idalib_hexrays_named_lvars(f);
  return vars == nullptr ? 0 : vars->size();
}

// Only return identities whose SDK serialization preserves the full location.
// In particular, vdloc_t uses all 32 register bits for a single microregister.
// Never deserialize caller-provided bytes into an SDK object.
inline rust::String idalib_hexrays_lvar_locator(ea_t entry_ea, const lvar_t &var) {
  const auto simple_location = [](const argloc_t &loc) {
    return loc.is_stkoff() || loc.is_reg() || loc.is_rrel() || loc.is_ea();
  };
  if (!simple_location(var.location)) {
    if (!var.location.is_scattered() || var.location.scattered().size() > 128) {
      return rust::String();
    }
    // No recursive or plugin-defined serialization. Each part is fixed-size.
    for (const argpart_t &part : var.location.scattered()) {
      if (!simple_location(part)) {
        return rust::String();
      }
    }
  }
  qtype encoded;
  if (var.width <= 0 || !append_argloc(&encoded, var.location)
      || encoded.empty() || encoded.length() > 4096) {
    return rust::String();
  }
  argloc_t decoded;
  const type_t *cursor = encoded.c_str();
  if (!extract_argloc(&decoded, &cursor, false)
      || cursor != encoded.c_str() + encoded.length()
      || compare_arglocs(decoded, var.location) != 0) {
    return rust::String();
  }
  qstring result;
  result.sprnt("lvar1:%d:%016llx:%016llx:%08x:", IDA_SDK_VERSION,
               static_cast<unsigned long long>(entry_ea),
               static_cast<unsigned long long>(var.defea),
               static_cast<unsigned int>(var.width));
  for (size_t i = 0; i < encoded.length(); ++i) {
    result.cat_sprnt("%02x", static_cast<unsigned int>(encoded[i]));
  }
  return rust::String(result.c_str());
}

inline bool idalib_hexrays_lvar_info(cfunc_t *f, size_t index,
                                     decompiler_lvar_info &out) {
  const lvars_t *vars = idalib_hexrays_named_lvars(f);
  if (vars == nullptr || index >= vars->size()) {
    return false;
  }
  const lvar_t &var = (*vars)[index];
  qstring location;
  print_vdloc(&location, var.location, var.width);
  qstring type_name;
  if (!var.type().print(&type_name)) {
    throw std::runtime_error("could not print local variable type");
  }
  out.name = rust::String(var.name.c_str());
  out.type_name = rust::String(type_name.c_str());
  out.location = rust::String(location.c_str());
  out.locator = idalib_hexrays_lvar_locator(f->entry_ea, var);
  out.definition_address = var.defea;
  out.width = var.width;
  out.is_argument = var.is_arg_var();
  out.has_user_name = var.has_user_name();
  out.has_user_type = var.has_user_type();
  return true;
}

inline lvar_t &idalib_hexrays_lvar_at(cfunc_t *f, size_t index) {
  lvars_t *vars = idalib_hexrays_named_lvars(f);
  if (vars == nullptr || index >= vars->size()) {
    throw std::runtime_error("local variable index is out of range");
  }
  return (*vars)[index];
}

inline void idalib_hexrays_rename_lvar(cfunc_t *f, size_t index,
                                      const char *name) {
  lvar_t &var = idalib_hexrays_lvar_at(f, index);
  qstring checked(name);
  if (checked.empty() || !validate_name(&checked, VNT_IDENT, 0) || checked != name) {
    throw std::runtime_error("invalid local variable name");
  }
  for (size_t i = 0; i < f->get_lvars()->size(); ++i) {
    if (i != index && (*f->get_lvars())[i].name == checked) {
      throw std::runtime_error("another local variable already has that name");
    }
  }
  lvar_saved_info_t info;
  info.ll = var;
  info.name = checked;
  if (!modify_user_lvar_info(f->entry_ea, MLI_NAME, info)) {
    throw std::runtime_error("Hex-Rays rejected the local variable name");
  }
  mark_cfunc_dirty(f->entry_ea, false);
}

inline rust::String idalib_hexrays_set_lvar_type(cfunc_t *f, size_t index,
                                                const char *decl) {
  lvar_t &var = idalib_hexrays_lvar_at(f, index);
  tinfo_t type;
  if (!parse_decl(&type, nullptr, nullptr, decl, PT_TYP | PT_SIL | PT_SEMICOLON)) {
    throw std::runtime_error("could not parse local variable type declaration");
  }
  // parse_decl can succeed with an empty type (for example, bare void).
  // Passing that to accepts_type raises a Hex-Rays internal exception.
  if (type.empty() || type.is_void() || type.is_func() || type.is_unknown()
      || !type.is_correct() || !var.accepts_type(type)) {
    throw std::runtime_error("Hex-Rays does not accept this type for the local variable");
  }
  qstring type_name;
  if (!type.print(&type_name)) {
    throw std::runtime_error("could not print local variable type");
  }
  rust::String result(type_name.c_str());
  lvar_saved_info_t info;
  info.ll = var;
  info.type = type;
  if (!modify_user_lvar_info(f->entry_ea, MLI_TYPE, info)) {
    throw std::runtime_error("Hex-Rays rejected the local variable type");
  }
  mark_cfunc_dirty(f->entry_ea, false);
  return result;
}
