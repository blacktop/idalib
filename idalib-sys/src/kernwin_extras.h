#pragma once

#include "auto.hpp"
#include "kernwin.hpp"
#include "license_seam.hpp"
#include "loader.hpp"
#include "pro.h"

#include <array>
#include <cstdint>

// IDA 9.5 made the license query API public (license.hpp / license_seam.hpp),
// replacing the reverse-engineered license_manager_t layout earlier branches
// probed and the always-true stub the 9.4 branch shipped.

inline bool idalib_check_license() { return is_license_valid(); }

/// End of the activation period as seconds since the Epoch (UTC);
/// 0 when there is no license or the license never expires.
inline int64_t idalib_license_end_date() { return get_license_end(); }

/// Fill `id` with the 6 raw bytes of the active license ID, parsed from the
/// seam's "XX-XXXX-XXXX-XX" hex form.
inline bool idalib_get_license_id(std::array<uint8_t, 6> &id) {
  char buf[64] = {};
  uint64_t needed = get_license_id_buf(buf, sizeof(buf));
  if (needed == 0 || needed > sizeof(buf)) {
    return false;
  }

  size_t count = 0;
  uint8_t pending = 0;
  bool high_nibble = true;
  for (const char *p = buf; *p != '\0'; ++p) {
    if (*p == '-') {
      continue;
    }
    int digit;
    if (*p >= '0' && *p <= '9') {
      digit = *p - '0';
    } else if (*p >= 'A' && *p <= 'F') {
      digit = *p - 'A' + 10;
    } else if (*p >= 'a' && *p <= 'f') {
      digit = *p - 'a' + 10;
    } else {
      return false;
    }
    if (high_nibble) {
      pending = static_cast<uint8_t>(digit << 4);
      high_nibble = false;
    } else {
      if (count >= id.size()) {
        return false;
      }
      id[count++] = static_cast<uint8_t>(pending | digit);
      high_nibble = true;
    }
  }

  return count == id.size() && high_nibble;
}

inline int idalib_open_database_quiet(int argc, const char *const *argv,
                               bool auto_analysis) {
  auto new_file = 0;
  auto result = init_database(argc, argv, &new_file);

  if (result != 0) {
    return result;
  }

  (*callui)(ui_notification_t::ui_ready_to_run);

  if (auto_analysis) {
    result = !auto_wait();
  }

  return result;
}

inline rust::String idalib_ea2str(ea_t ea) {
  auto out = qstring();

  if (ea2str(&out, ea)) {
    return rust::String(out.c_str());
  } else {
    return rust::String();
  }
}

inline bool idalib_load_dbg_dbginfo(const char *path, bool verbose) {
  return load_dbg_dbginfo(path, nullptr, BADADDR, verbose);
}
