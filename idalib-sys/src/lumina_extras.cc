#include "cxxgen1.h"

#include "lumina.hpp"
#include "lumina_extras.h"

#include <memory>

namespace {

void set_error(lumina_pull_result &out, const qstring &error) {
  out.error = rust::String(error.c_str());
}

} // namespace

bool idalib_lumina_pull(
    std::uint64_t ea,
    bool apply,
    bool force,
    lumina_pull_result &out) {
  out.code = PDRES_ERROR;

  lumina_client_t *client = get_server_connection();
  if (client == nullptr) {
    out.error = rust::String("Lumina server connection is unavailable");
    return false;
  }
  eavec_t functions;
  functions.push_back(static_cast<ea_t>(ea));
  qstring error;
  const std::uint32_t flags = apply ? 0 : PULL_MD_SEEN_FILE;
  std::unique_ptr<pkt_pull_md_result_t> result(
      client->pull_md(&functions, &error, flags));
  if (result == nullptr) {
    set_error(out, error);
    return false;
  }
  if (result->codes.empty()) {
    out.error = rust::String("Lumina returned no status for the function");
    return false;
  }

  out.code = static_cast<std::int32_t>(result->codes[0]);
  if (result->codes[0] != PDRES_OK) {
    set_error(out, error);
    return true;
  }
  if (result->results.empty()) {
    out.error = rust::String("Lumina reported a match without metadata");
    return false;
  }

  const func_info_and_frequency_t &info = result->results[0];
  out.name = rust::String(info.name.c_str());
  out.size = info.size;
  out.frequency = info.frequency;
  out.score = score_metadata(info);

  for (int key = MDK_TYPE; key < MDK_LAST; ++key) {
    if (info.metadata.find(static_cast<mdkey_t>(key)) != nullptr) {
      out.metadata_mask |= std::uint32_t(1) << key;
    }
  }

  if (apply) {
    out.backup_created = backup_metadata(static_cast<ea_t>(ea));
    apply_metadata(
        static_cast<ea_t>(ea),
        info,
        force ? AMDF_FORCE : AMDF_UPGRADE);
    out.applied = true;
  }
  return true;
}
