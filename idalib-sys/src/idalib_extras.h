#pragma once

#include "idalib.hpp"
#include "kernwin.hpp"

bool idalib_get_library_version(int *major, int *minor, int *build) {
  return get_library_version(*major, *minor, *build);
}

void idalib_set_batch_mode(bool enable) {
  batch = enable;
}
