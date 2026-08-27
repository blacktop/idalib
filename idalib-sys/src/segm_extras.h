#pragma once

#include "pro.h"
#include "bytes.hpp"
#include "ida.hpp"
#include "nalt.hpp"
#include "segment.hpp"

#include <cstdint>
#include <exception>
#include <limits>
#include <memory>

#include "cxx.h"

inline rust::String idalib_segm_name(const segment_t *s) {
  auto name = qstring();

  if (get_segm_name(&name, s) > 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

inline std::size_t idalib_segm_bytes(const segment_t *s, rust::Vec<rust::u8>& buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), s->start_ea, GMB_READALL); sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}

inline std::uint8_t idalib_segm_align(const segment_t *s) {
  return s->align;
}

inline std::uint8_t idalib_segm_bitness(const segment_t *s) {
  return s->bitness;
}

inline std::uint8_t idalib_segm_perm(const segment_t *s) {
  return s->perm;
}

inline std::uint8_t idalib_segm_type(const segment_t *s) {
  return s->type;
}

inline bool idalib_set_segment_addressing(std::uint64_t ea,
                                           std::size_t bitness) {
  return set_segment_addressing(ea, bitness);
}

inline std::int32_t idalib_rebase_program(std::uint64_t new_base) {
  const auto current_base = get_imagebase();
  const auto target_base = static_cast<ea_t>(new_base);
  if (static_cast<std::uint64_t>(target_base) != new_base) {
    return MOVE_SEGM_PARAM;
  }
  if (target_base == current_base) {
    inf_set_baseaddr(target_base >> 4);
    return MOVE_SEGM_OK;
  }

  adiff_t delta = 0;
  if (target_base >= current_base) {
    const auto distance = target_base - current_base;
    if (distance > static_cast<ea_t>(std::numeric_limits<adiff_t>::max())) {
      return MOVE_SEGM_PARAM;
    }
    delta = static_cast<adiff_t>(distance);
  } else {
    const auto distance = current_base - target_base;
    const auto max_negative_distance =
        static_cast<ea_t>(std::numeric_limits<adiff_t>::max()) + 1;
    if (distance > max_negative_distance) {
      return MOVE_SEGM_PARAM;
    }
    delta = distance == max_negative_distance
                ? std::numeric_limits<adiff_t>::min()
                : -static_cast<adiff_t>(distance);
  }

  const auto result = rebase_program(delta, MSF_SILENT | MSF_FIXONCE);
  if (result == MOVE_SEGM_OK) {
    set_imagebase(target_base);
    inf_set_baseaddr(target_base >> 4);
  }
  return result;
}
