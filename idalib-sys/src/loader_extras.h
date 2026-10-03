#pragma once

#include "loader.hpp"

#include <cstdint>

#include "cxx.h"

inline uint64_t idalib_plugin_version(const plugin_t *p) {
  return p == nullptr ? 0 : p->version;
}

// Writes the open database to its own path without closing it.
inline bool idalib_save_database() {
  return save_database(nullptr, 0);
}

// Full path of the open database file (not the input binary).
inline rust::String idalib_idb_path() {
  const char *path = get_path(PATH_TYPE_IDB);
  return path == nullptr ? rust::String() : rust::String(path);
}

inline uint64_t idalib_plugin_flags(const plugin_t *p) {
  return p == nullptr ? 0 : p->flags;
}
