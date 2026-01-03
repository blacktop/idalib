#include "cxxgen1.h"
#include "typeinf.hpp"

uint32 idalib_get_ordinal_limit() {
  return get_ordinal_limit(nullptr);
}

bool idalib_get_udt_info(uint32 ordinal, udt_info &out) {
  tinfo_t tif;
  if (!tif.get_numbered_type(nullptr, ordinal, BTF_TYPEDEF, true)) {
    return false;
  }
  if (!(tif.is_struct() || tif.is_union())) {
    return false;
  }

  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt, GTD_CALC_LAYOUT)) {
    return false;
  }

  const char *name = get_numbered_type_name(nullptr, ordinal);
  out.name = name ? rust::String(name) : rust::String();
  out.size = static_cast<uint64>(udt.total_size);
  out.is_union = udt.is_union;
  out.member_count = static_cast<uint32>(udt.size());
  return true;
}

bool idalib_get_udt_member(uint32 ordinal, uint32 index, udt_member_info &out) {
  tinfo_t tif;
  if (!tif.get_numbered_type(nullptr, ordinal, BTF_TYPEDEF, true)) {
    return false;
  }
  if (!(tif.is_struct() || tif.is_union())) {
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
  return true;
}

bool idalib_get_udt_member_tid(uint32 ordinal, uint32 index, uint64_t &out_tid) {
  tinfo_t tif;
  if (!tif.get_numbered_type(nullptr, ordinal, BTF_TYPEDEF, true)) {
    return false;
  }
  if (!(tif.is_struct() || tif.is_union())) {
    return false;
  }

  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt, GTD_CALC_LAYOUT)) {
    return false;
  }
  if (index >= udt.size()) {
    return false;
  }

  tid_t tid = tif.get_udm_tid(index);
  if (tid == BADADDR) {
    return false;
  }
  out_tid = static_cast<uint64_t>(tid);
  return true;
}
