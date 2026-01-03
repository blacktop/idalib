#pragma once

#include "cxx.h"
#include <cstdint>

struct local_type_info;
struct type_decl_result;
struct type_guess_result;

bool idalib_get_local_type(uint32 ordinal, local_type_info &out);
bool idalib_declare_type(const char *decl, bool relaxed, bool replace, type_decl_result &out);
int idalib_declare_types(const char *decls, bool relaxed);
bool idalib_apply_decl_type(uint64_t ea, const char *decl, bool relaxed, bool delay, bool strict);
bool idalib_apply_named_type(uint64_t ea, const char *name);
bool idalib_guess_tinfo(uint64_t id, type_guess_result &out);
