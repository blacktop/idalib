#pragma once

#include "loader.hpp"

#include <cstdint>
#include <cstring>

#include "cxx.h"

inline uint64_t idalib_plugin_version(const plugin_t *p) {
  return p == nullptr ? 0 : p->version;
}

inline uint64_t idalib_plugin_flags(const plugin_t *p) {
  return p == nullptr ? 0 : p->flags;
}

inline bool idalib_set_database_path(const char *path) {
  set_path(PATH_TYPE_IDB, path);
  return std::strcmp(get_path(PATH_TYPE_IDB), path) == 0;
}
