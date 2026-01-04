#pragma once

#include <auto.hpp>

inline bool idalib_auto_is_ok() { return auto_is_ok(); }

inline int idalib_get_auto_state() { return static_cast<int>(get_auto_state()); }
