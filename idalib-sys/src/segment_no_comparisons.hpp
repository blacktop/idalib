#pragma once

// IDA 9.4's Windows ARM64 import library omits segment_t::compare. It is not
// used by idalib, so exclude only that declaration from autocxx generation.
#pragma push_macro("DECLARE_COMPARISONS")
#undef DECLARE_COMPARISONS
#define DECLARE_COMPARISONS(type)
#include "segment.hpp"
#undef DECLARE_COMPARISONS
#pragma pop_macro("DECLARE_COMPARISONS")
