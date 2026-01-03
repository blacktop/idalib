#pragma once

#include <cstdint>
#include "cxx.h"

struct frame_info;
struct frame_member_info;
struct stkvar_result;

bool idalib_get_frame_info(uint64_t ea, frame_info &out);
bool idalib_get_frame_member(uint64_t ea, uint32 index, frame_member_info &out);
bool idalib_define_stkvar(
    uint64_t ea,
    const char *name,
    int64_t offset,
    const char *decl,
    bool relaxed,
    stkvar_result &out);
bool idalib_delete_stkvar(
    uint64_t ea,
    const char *name,
    int64_t offset,
    bool use_offset,
    stkvar_result &out);
bool idalib_set_stkvar_type(
    uint64_t ea,
    const char *name,
    int64_t offset,
    bool use_offset,
    const char *decl,
    bool relaxed,
    bool strict,
    stkvar_result &out);
