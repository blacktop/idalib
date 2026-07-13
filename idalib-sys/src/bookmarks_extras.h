#pragma once

#include "moves.hpp"

#include "cxx.h"

inline rust::u32 idalib_bookmarks_t_mark(ea_t ea, uint32 index, const char *desc) {
  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_mark(e, index, nullptr, desc, nullptr);
}

inline rust::String idalib_bookmarks_t_get_desc(uint32 index) {
  auto desc = qstring();
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  if (bookmarks_t_get_desc(&desc, e, index, nullptr) != 0) {
    return rust::String(desc.c_str());
  } else {
    return rust::String();
  }
}

inline ea_t idalib_bookmarks_t_get(uint32 index) {
  auto desc = qstring();
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  lochist_entry_t loc(e);

  if (bookmarks_t_get(&loc, &desc, &index, nullptr) != 0) {
    return loc.place()->toea();
  } else {
    return BADADDR;
  }
}

inline bool idalib_bookmarks_t_erase(uint32 index) {
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_erase(e, index, nullptr);
}

inline rust::u32 idalib_bookmarks_t_find_index(ea_t ea) {
  auto widget = qstring();
  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_find_index(e, nullptr);
}

inline rust::u32 idalib_bookmarks_t_size(void) {
  auto widget = qstring();
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_size(e, nullptr);
}
