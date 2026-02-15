#pragma once

#include <cstdint>
#include "cxx.h"

struct script_result;

// Execute a Python code snippet via the IDAPython extlang.
// Captures stdout/stderr via StringIO redirect.
// Returns false if the Python extlang is unavailable.
bool idalib_run_python_snippet(rust::Str code, script_result &out);
