#pragma once

// IDA 9.4's Windows ARM64 import library omits func_t::compare. Keep the
// struct's ABI intact while omitting that unused declaration from autocxx.
#pragma push_macro("DECLARE_COMPARISONS")
#undef DECLARE_COMPARISONS
#define DECLARE_COMPARISONS(type) IDALIB_AUTOCXX_DECLARE_COMPARISONS_##type
#define IDALIB_AUTOCXX_DECLARE_COMPARISONS_regarg_t \
  DECLARE_COMPARISON_OPERATORS(regarg_t) \
  int compare(const regarg_t &r) const
#define IDALIB_AUTOCXX_DECLARE_COMPARISONS_func_t
#include "funcs.hpp"
#undef IDALIB_AUTOCXX_DECLARE_COMPARISONS_func_t
#undef IDALIB_AUTOCXX_DECLARE_COMPARISONS_regarg_t
#undef DECLARE_COMPARISONS
#pragma pop_macro("DECLARE_COMPARISONS")
