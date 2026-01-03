#include "cxxgen1.h"
#include "frame.hpp"
#include "typeinf.hpp"

static bool in_range(const range_t &range, uval_t off) {
  if (range.start_ea <= range.end_ea) {
    return off >= range.start_ea && off < range.end_ea;
  }
  return off < range.start_ea && off >= range.end_ea;
}

static rust::String part_from_offset(const func_t *pfn, uval_t off) {
  range_t args;
  range_t retaddr;
  range_t savregs;
  range_t lvars;
  get_frame_part(&args, pfn, FPC_ARGS);
  get_frame_part(&retaddr, pfn, FPC_RETADDR);
  get_frame_part(&savregs, pfn, FPC_SAVREGS);
  get_frame_part(&lvars, pfn, FPC_LVARS);

  if (in_range(args, off)) {
    return rust::String("args");
  }
  if (in_range(retaddr, off)) {
    return rust::String("retaddr");
  }
  if (in_range(savregs, off)) {
    return rust::String("savregs");
  }
  if (in_range(lvars, off)) {
    return rust::String("locals");
  }
  return rust::String("unknown");
}

bool idalib_get_frame_info(uint64_t ea, frame_info &out) {
  func_t *pfn = get_func(static_cast<ea_t>(ea));
  if (pfn == nullptr) {
    return false;
  }

  tinfo_t tif;
  if (!get_func_frame(&tif, pfn)) {
    return false;
  }

  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt, GTD_CALC_LAYOUT)) {
    return false;
  }

  range_t args;
  range_t retaddr;
  range_t savregs;
  range_t lvars;
  get_frame_part(&args, pfn, FPC_ARGS);
  get_frame_part(&retaddr, pfn, FPC_RETADDR);
  get_frame_part(&savregs, pfn, FPC_SAVREGS);
  get_frame_part(&lvars, pfn, FPC_LVARS);

  out.frame_size = static_cast<uint64>(get_frame_size(pfn));
  out.ret_size = static_cast<int32>(get_frame_retsize(pfn));
  out.frsize = static_cast<uint64>(pfn->frsize);
  out.frregs = static_cast<uint16>(pfn->frregs);
  out.argsize = static_cast<uint64>(pfn->argsize);
  out.fpd = static_cast<uint64>(pfn->fpd);

  out.args_start = static_cast<uint64>(args.start_ea);
  out.args_end = static_cast<uint64>(args.end_ea);
  out.retaddr_start = static_cast<uint64>(retaddr.start_ea);
  out.retaddr_end = static_cast<uint64>(retaddr.end_ea);
  out.savregs_start = static_cast<uint64>(savregs.start_ea);
  out.savregs_end = static_cast<uint64>(savregs.end_ea);
  out.locals_start = static_cast<uint64>(lvars.start_ea);
  out.locals_end = static_cast<uint64>(lvars.end_ea);

  out.member_count = static_cast<uint32>(udt.size());
  return true;
}

bool idalib_get_frame_member(uint64_t ea, uint32 index, frame_member_info &out) {
  func_t *pfn = get_func(static_cast<ea_t>(ea));
  if (pfn == nullptr) {
    return false;
  }

  tinfo_t tif;
  if (!get_func_frame(&tif, pfn)) {
    return false;
  }

  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt, GTD_CALC_LAYOUT)) {
    return false;
  }
  if (index >= udt.size()) {
    return false;
  }

  const udm_t &m = udt.at(index);
  out.name = rust::String(m.name.c_str());
  out.type_name = rust::String(m.type.dstr());
  out.offset_bits = m.offset;
  out.size_bits = m.size;
  out.is_bitfield = m.is_bitfield();

  uval_t off = static_cast<uval_t>(m.offset / 8);
  out.part = part_from_offset(pfn, off);
  return true;
}

static bool get_frame_udt(const func_t *pfn, tinfo_t &tif, udt_type_data_t &udt) {
  if (pfn == nullptr) {
    return false;
  }
  if (!get_func_frame(&tif, pfn)) {
    return false;
  }
  if (!tif.get_udt_details(&udt, GTD_CALC_LAYOUT)) {
    return false;
  }
  return true;
}

static ssize_t find_frame_member(
    const func_t *pfn,
    const udt_type_data_t &udt,
    const char *name,
    int64_t offset,
    bool use_offset) {
  if (name != nullptr && name[0] != '\0') {
    for (size_t i = 0; i < udt.size(); i++) {
      const udm_t &m = udt.at(i);
      if (m.name == name) {
        return static_cast<ssize_t>(i);
      }
    }
  }

  if (use_offset) {
    sval_t frame_off = calc_frame_offset(const_cast<func_t *>(pfn), static_cast<sval_t>(offset));
    if (frame_off == BADADDR) {
      frame_off = static_cast<sval_t>(offset);
    }
    for (size_t i = 0; i < udt.size(); i++) {
      const udm_t &m = udt.at(i);
      if (static_cast<sval_t>(m.offset / 8) == frame_off) {
        return static_cast<ssize_t>(i);
      }
    }
  }
  return -1;
}

bool idalib_define_stkvar(
    uint64_t ea,
    const char *name,
    int64_t offset,
    const char *decl,
    bool relaxed,
    stkvar_result &out) {
  out.code = TERR_BAD_TYPE;
  out.offset = offset;
  out.name = name ? rust::String(name) : rust::String();

  func_t *pfn = get_func(static_cast<ea_t>(ea));
  if (pfn == nullptr) {
    out.code = TERR_BAD_ARG;
    return false;
  }

  tinfo_t tif;
  qstring tname;
  int pt_flags = PT_TYP | PT_SIL | PT_SEMICOLON;
  if (relaxed) {
    pt_flags |= PT_RELAXED;
  }
  if (!parse_decl(&tif, &tname, nullptr, decl, pt_flags)) {
    out.code = TERR_BAD_TYPE;
    return false;
  }

  const char *stk_name = (name != nullptr && name[0] != '\0') ? name : nullptr;
  bool ok = define_stkvar(pfn, stk_name, static_cast<sval_t>(offset), tif, nullptr);
  if (!ok) {
    out.code = TERR_BAD_TYPE;
    return false;
  }

  if (stk_name == nullptr) {
    qstring auto_name;
    if (build_stkvar_name(&auto_name, pfn, static_cast<sval_t>(offset)) >= 0) {
      out.name = rust::String(auto_name.c_str());
    }
  }

  out.code = TERR_OK;
  return true;
}

bool idalib_delete_stkvar(
    uint64_t ea,
    const char *name,
    int64_t offset,
    bool use_offset,
    stkvar_result &out) {
  out.code = TERR_BAD_ARG;
  out.offset = offset;
  out.name = name ? rust::String(name) : rust::String();

  func_t *pfn = get_func(static_cast<ea_t>(ea));
  if (pfn == nullptr) {
    return false;
  }

  tinfo_t tif;
  udt_type_data_t udt;
  if (!get_frame_udt(pfn, tif, udt)) {
    return false;
  }

  ssize_t idx = find_frame_member(pfn, udt, name, offset, use_offset);
  if (idx < 0) {
    out.code = TERR_NOT_FOUND;
    return false;
  }

  tinfo_code_t code = tif.del_udm(static_cast<size_t>(idx), 0);
  out.code = code;
  if (code != TERR_OK) {
    return false;
  }

  out.name = rust::String(udt.at(static_cast<size_t>(idx)).name.c_str());
  return true;
}

bool idalib_set_stkvar_type(
    uint64_t ea,
    const char *name,
    int64_t offset,
    bool use_offset,
    const char *decl,
    bool relaxed,
    bool strict,
    stkvar_result &out) {
  out.code = TERR_BAD_TYPE;
  out.offset = offset;
  out.name = name ? rust::String(name) : rust::String();

  func_t *pfn = get_func(static_cast<ea_t>(ea));
  if (pfn == nullptr) {
    out.code = TERR_BAD_ARG;
    return false;
  }

  tinfo_t frame_tif;
  udt_type_data_t udt;
  if (!get_frame_udt(pfn, frame_tif, udt)) {
    out.code = TERR_BAD_TYPE;
    return false;
  }

  ssize_t idx = find_frame_member(pfn, udt, name, offset, use_offset);
  if (idx < 0) {
    out.code = TERR_NOT_FOUND;
    return false;
  }

  tinfo_t tif;
  qstring tname;
  int pt_flags = PT_TYP | PT_SIL | PT_SEMICOLON;
  if (relaxed) {
    pt_flags |= PT_RELAXED;
  }
  if (!parse_decl(&tif, &tname, nullptr, decl, pt_flags)) {
    out.code = TERR_BAD_TYPE;
    return false;
  }

  uint etf_flags = 0;
  if (strict) {
    etf_flags |= ETF_NO_ARRAY;
  }
  tinfo_code_t code = frame_tif.set_udm_type(static_cast<size_t>(idx), tif, etf_flags, nullptr);
  out.code = code;
  if (code != TERR_OK) {
    return false;
  }

  out.name = rust::String(udt.at(static_cast<size_t>(idx)).name.c_str());
  return true;
}
