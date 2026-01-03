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
