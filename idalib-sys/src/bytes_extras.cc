#include "cxxgen1.h"

#include "bytes_extras.h"

static int idaapi collect_patched_byte(ea_t ea, qoff64_t fpos, uint64 original,
                                       uint64 patched, void *user_data) {
  auto *out = static_cast<rust::Vec<patched_byte_info> *>(user_data);
  patched_byte_info info;
  info.address = static_cast<std::uint64_t>(ea);
  info.file_offset = static_cast<std::int64_t>(fpos);
  info.original_value = static_cast<std::uint64_t>(original);
  info.patched_value = static_cast<std::uint64_t>(patched);
  out->push_back(std::move(info));
  return 0;
}

bool idalib_visit_patched_bytes(ea_t start, ea_t end,
                                rust::Vec<patched_byte_info> &out) {
  return visit_patched_bytes(start, end, collect_patched_byte, &out) == 0;
}
