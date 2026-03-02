#pragma once

#include "hexrays.hpp"
#include "lines.hpp"
#include "pro.h"

#include <cstdint>
#include <memory>
#include <sstream>

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

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

std::unique_ptr<cfuncptr_t>
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

rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

cblock_t *idalib_hexrays_cfunc_body(cfunc_t *f) {
  if (f == nullptr) {
    return nullptr;
  }
  return f->body.cblock;
}

std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }

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
bool idalib_hexrays_cfunc_has_eamap(cfunc_t *f) {
  return (f->statebits & CFS_BOUNDS) != 0;
}

/// Find statements at a specific address. Returns nullptr if not found.
std::unique_ptr<eamap_result> idalib_hexrays_cfunc_find_stmts_at(cfunc_t *f,
                                                                 ea_t addr) {
  eamap_t &em = f->get_eamap();
  auto it = eamap_find(&em, addr);
  if (it == eamap_end(&em)) {
    return nullptr;
  }
  return std::unique_ptr<eamap_result>(new eamap_result(&eamap_second(it)));
}

/// Get the number of statements at this address
std::size_t idalib_hexrays_eamap_result_len(const eamap_result &r) {
  return r.vec ? r.vec->size() : 0;
}

/// Get the next statement from the result, or nullptr if exhausted
cinsn_t *idalib_hexrays_eamap_result_next(eamap_result &r) {
  if (!r.vec || r.index >= r.vec->size()) {
    return nullptr;
  }
  return r.vec->at(r.index++);
}

/// Reset the iterator to the beginning
void idalib_hexrays_eamap_result_reset(eamap_result &r) { r.index = 0; }

/// Get the address (ea) of a cinsn_t
ea_t idalib_hexrays_cinsn_ea(const cinsn_t *insn) { return insn->ea; }

/// Get the opcode of a cinsn_t (cit_* constants)
int idalib_hexrays_cinsn_op(const cinsn_t *insn) { return insn->op; }

/// Print a single ctree item (cinsn_t or cexpr_t) as text
rust::String idalib_hexrays_citem_print(const citem_t *item,
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
rust::String idalib_hexrays_cinsn_print(const cinsn_t *insn,
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
bool idalib_hexrays_cfunc_get_stmt_bounds(cfunc_t *f, const cinsn_t *insn,
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
