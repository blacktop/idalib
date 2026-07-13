#pragma once

#include "bytes.hpp"

#include "cxx.h"

inline std::uint8_t idalib_get_byte(ea_t ea) { return get_byte(ea); }
inline std::uint16_t idalib_get_word(ea_t ea) { return get_word(ea); }
inline std::uint32_t idalib_get_dword(ea_t ea) { return get_dword(ea); }
inline std::uint64_t idalib_get_qword(ea_t ea) { return get_qword(ea); }

inline std::size_t idalib_get_bytes(ea_t ea, rust::Vec<rust::u8> &buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), ea, GMB_READALL);
      sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}

inline bool idalib_patch_bytes(ea_t ea, rust::Vec<rust::u8> &buf) {
  if (buf.size() == 0) {
    return true;
  }
  patch_bytes(ea, buf.data(), buf.size());
  return true;
}
