#pragma once

#include <registry.hpp>

inline void idalib_reg_write_bool(const char *name, bool value) {
  reg_write_bool(name, value);
}

inline bool idalib_reg_read_bool(const char *name, bool default_value) {
  return reg_read_bool(name, default_value);
}
