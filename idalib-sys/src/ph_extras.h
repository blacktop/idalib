#pragma once

#include "pro.h"
#include "ida.hpp"
#include "idp.hpp"
#include "segment.hpp"
#include "segregs.hpp"

#include "cxx.h"

std::int32_t idalib_ph_id(const processor_t *ph) {
  return ph->id;
}

rust::String idalib_ph_short_name(const processor_t *ph) {
  auto name = ph->psnames[const_cast<processor_t *>(ph)->get_proc_index()];
  return rust::String(name);
}

rust::String idalib_ph_long_name(const processor_t *ph) {
  auto name = ph->plnames[const_cast<processor_t *>(ph)->get_proc_index()];
  return rust::String(name);
}

bool idalib_is_thumb_at(const processor_t *ph, ea_t ea) {
  const auto T = 20;

  if (ph->id == PLFM_ARM && !inf_is_64bit()) {
    auto tbit = get_sreg(ea, T);
    return tbit != 0 && tbit != BADSEL;
  }
  return false;
}

long long idalib_assemble_line(ea_t ea, const char *line,
                               rust::Vec<rust::u8> &out) {
  const processor_t *ph = get_ph();
  if (ph == nullptr) {
    return -1;
  }
  if ((ph->flag & PR_ASSEMBLE) == 0) {
    return -1;
  }

  set_target_assembler(inf_get_asmtype());

  ea_t cs = BADADDR;
  bool use32 = false;
  if (segment_t *seg = getseg(ea); seg != nullptr) {
    cs = seg->sel;
    use32 = seg->bitness == 1;
  } else {
    use32 = inf_is_32bit_exactly();
  }

  constexpr size_t kAssembleBufSize = MAXSTR;
  out.reserve(kAssembleBufSize);
  const size_t cap = out.capacity();
  if (cap < kAssembleBufSize) {
    return -1;
  }
  auto try_assemble = [&](ea_t cs_val, bool use32_val) -> long long {
    return ph->assemble(out.data(), ea, cs_val, ea, use32_val, line);
  };

  long long len = try_assemble(cs, use32);
  if (len <= 0 && cs != BADADDR) {
    len = try_assemble(BADADDR, use32);
  }
  if (len <= 0) {
    len = try_assemble(cs, !use32);
  }
  if (len <= 0 && cs != BADADDR) {
    len = try_assemble(BADADDR, !use32);
  }
  return len;
}
