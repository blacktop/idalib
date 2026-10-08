#include "cxxgen1.h"

#include "hexrays_extras.h"

#include <cstring>
#include <set>
#include <string_view>

static rust::String idalib_hexrays_comment_locator(ea_t entry,
                                                   const treeloc_t &loc) {
  qstring result;
  result.sprnt("pcmt1:%d:%llx:%llx:%x", IDA_SDK_VERSION,
               static_cast<unsigned long long>(entry),
               static_cast<unsigned long long>(loc.ea),
               static_cast<unsigned>(loc.itp));
  return rust::String(result.c_str());
}

rust::Vec<decompiler_comment_location>
idalib_hexrays_comment_locations(cfunc_t *f) {
  if (f == nullptr) {
    throw std::runtime_error("missing decompilation");
  }
  const strvec_t &lines = f->get_pseudocode();
  constexpr size_t max_lines = 100000;
  constexpr size_t max_bytes = 16 * 1024 * 1024;
  if (lines.size() > max_lines) {
    throw std::runtime_error("too many pseudocode lines for comment selection");
  }
  std::set<treeloc_t> seen;
  rust::Vec<decompiler_comment_location> result;
  size_t remaining = max_bytes;
  for (size_t i = 0; i < lines.size(); ++i) {
    if (i < static_cast<size_t>(qmax(f->hdrlines, 0))) {
      continue;
    }
    const qstring &line = lines[i].line;
    if (line.length() > remaining) {
      throw std::runtime_error("pseudocode comment selection exceeds size limit");
    }
    remaining -= line.length();
    ctree_item_t tail;
    // A valid tail is returned even when no cursor item exists (e.g. else).
    f->get_line_item(line.c_str(), 0, true, nullptr, nullptr, &tail);
    if (tail.citype != VDI_TAIL || tail.loc.ea == BADADDR
        || tail.loc.itp == ITP_EMPTY) {
      continue;
    }
    qstring text;
    tag_remove(&text, line);
    const std::string_view visible(text.c_str(), text.length());
    const size_t first = visible.find_first_not_of(" \t");
    // Comment-only lines (block comments, multiline continuations) can carry
    // a statement's tail, but they are not code locations.
    if (first == std::string_view::npos || visible.compare(first, 2, "//") == 0) {
      continue;
    }
    // Several lines can share one location. The printer retrieves each comment
    // once (RETRIEVE_ONCE), so it renders on the first line with that tail.
    if (!seen.insert(tail.loc).second) {
      continue;
    }
    const char *comment = f->get_user_cmt(tail.loc, RETRIEVE_ALWAYS);
    size_t comment_size = 0;
    if (comment != nullptr) {
      comment_size = strnlen(comment, remaining + 1);
      if (comment_size > remaining) {
        throw std::runtime_error("pseudocode comments exceed size limit");
      }
      remaining -= comment_size;
    }
    result.push_back({idalib_hexrays_comment_locator(f->entry_ea, tail.loc),
                      tail.loc.ea, static_cast<uint32_t>(tail.loc.itp),
                      static_cast<uint32_t>(i + 1), rust::String(text.c_str()),
                      rust::String(comment == nullptr ? "" : comment, comment_size)});
  }
  return result;
}

void idalib_hexrays_set_pseudocode_comment(cfunc_t *f,
                                          const char *locator,
                                          const char *comment) {
  if (locator == nullptr || comment == nullptr) {
    throw std::runtime_error("invalid pseudocode comment input");
  }
  const size_t locator_length = strlen(locator);
  if (locator_length == 0 || locator_length > 128 || strlen(comment) > 16384) {
    throw std::runtime_error("invalid pseudocode comment input");
  }
  // Never decode an outside locator into a native location: stale locations
  // can otherwise create orphaned edits. Match a current rendered location.
  const auto locations = idalib_hexrays_comment_locations(f);
  for (const auto &candidate : locations) {
    if (candidate.locator != locator) {
      continue;
    }
    treeloc_t loc{candidate.address,
                 static_cast<item_preciser_t>(candidate.placement)};
    f->set_user_cmt(loc, comment);
    f->save_user_cmts();
    mark_cfunc_dirty(f->entry_ea, false);
    return;
  }
  throw std::runtime_error("pseudocode comment locator is stale or does not "
                           "belong to this function; list comment locations "
                           "again");
}
