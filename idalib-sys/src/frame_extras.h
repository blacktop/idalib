#pragma once

#include <cstdint>
#include "cxx.h"

struct frame_info;
struct frame_member_info;

bool idalib_get_frame_info(uint64_t ea, frame_info &out);
bool idalib_get_frame_member(uint64_t ea, uint32 index, frame_member_info &out);
