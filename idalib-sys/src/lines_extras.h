#pragma once

#include "lines.hpp"
#include "pro.h"

#include "cxx.h"

/// Generate a disassembly line at the given address, with IDA color codes stripped.
/// Returns an empty string if the address is invalid or no disassembly is available.
rust::String idalib_generate_disasm_line(ea_t ea) {
  qstring buf;

  // GENDSM_FORCE_CODE = 0x0001 - generate code even if the address contains data
  if (generate_disasm_line(&buf, ea, 0)) {
    qstring clean;
    tag_remove(&clean, buf);
    return rust::String(clean.c_str());
  }

  return rust::String("");
}
