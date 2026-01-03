#pragma once

#include "cxx.h"

struct local_type_info;

bool idalib_get_local_type(uint32 ordinal, local_type_info &out);
