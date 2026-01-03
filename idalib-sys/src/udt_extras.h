#pragma once

#include <cstdint>
#include "cxx.h"

struct udt_info;
struct udt_member_info;

// Helpers for user-defined types (structs/unions) via type information.
uint32 idalib_get_ordinal_limit();
bool idalib_get_udt_info(uint32 ordinal, udt_info &out);
bool idalib_get_udt_member(uint32 ordinal, uint32 index, udt_member_info &out);
bool idalib_get_udt_member_tid(uint32 ordinal, uint32 index, uint64_t &out_tid);
