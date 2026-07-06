#include "cxxgen1.h"

#include "dscu.h"
#include "dscu_extras.h"

#include <limits>

static dscu_svc_t *svc() {
  return get_dscu_svc();
}

static std::size_t max_count_to_size(std::uint64_t max_count) {
  const auto max_size = std::numeric_limits<std::size_t>::max();
  if (max_count >= static_cast<std::uint64_t>(max_size)) {
    return max_size;
  }
  return static_cast<std::size_t>(max_count);
}

static rust::String string_view_to_rust(std::string_view view) {
  return rust::String(view.data(), view.size());
}

static void fill_region_info(const region_info_t &ri, dscu_region_info &out) {
  out.start = static_cast<std::uint64_t>(ri.start);
  out.size = static_cast<std::uint64_t>(ri.size);
  out.region_type = static_cast<std::int32_t>(ri.type);
  out.image_index = static_cast<std::int32_t>(ri.image_index);
  out.name = rust::String(ri.name);
}

static bool fill_image_info(dscu_svc_t *ds, std::int32_t image_index, dscu_image_info &out) {
  if (ds == nullptr || image_index < 0) {
    return false;
  }

  qstring name;
  if (!ds->get_image_name(&name, image_index)) {
    return false;
  }

  qstring file_name;
  ds->get_image_file_name(&file_name, image_index);

  out.index = image_index;
  out.name = rust::String(name.c_str());
  out.file_name = rust::String(file_name.c_str());
  out.address = static_cast<std::uint64_t>(ds->get_image_address(image_index));
  out.total_size = static_cast<std::uint64_t>(ds->get_image_total_size(image_index));
  const auto file_index = ds->get_image_file_index(image_index);
  out.file_index = file_index == std::size_t(-1) ? -1 : static_cast<std::int64_t>(file_index);
  out.loaded = ds->is_image_loaded(image_index);
  return true;
}

bool idalib_dscu_available() {
  return svc() != nullptr;
}

rust::String idalib_dscu_input_file_path() {
  dscu_svc_t *ds = svc();
  if (ds == nullptr) {
    return rust::String();
  }

  qstring path;
  if (!ds->get_input_file_path(&path)) {
    return rust::String();
  }
  return rust::String(path.c_str());
}

std::int32_t idalib_dscu_images_count() {
  dscu_svc_t *ds = svc();
  return ds == nullptr ? -1 : static_cast<std::int32_t>(ds->get_images_count());
}

std::int32_t idalib_dscu_get_image_index(const char *name) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr || name == nullptr || name[0] == '\0') {
    return -1;
  }
  return static_cast<std::int32_t>(ds->get_image_index(name));
}

bool idalib_dscu_get_image_info(std::int32_t image_index, dscu_image_info &out) {
  return fill_image_info(svc(), image_index, out);
}

bool idalib_dscu_get_images(rust::Vec<dscu_image_info> &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr) {
    return false;
  }

  const int count = ds->get_images_count();
  for (int i = 0; i < count; i++) {
    dscu_image_info info;
    if (fill_image_info(ds, i, info)) {
      out.push_back(info);
    }
  }
  return true;
}

bool idalib_dscu_get_image_dependencies(
    std::int32_t image_index,
    std::int32_t depth,
    rust::Vec<dscu_image_info> &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr || image_index < 0) {
    return false;
  }

  intvec_t indexes;
  if (!ds->get_image_dependencies(&indexes, image_index, depth)) {
    return false;
  }

  for (int index : indexes) {
    dscu_image_info info;
    if (fill_image_info(ds, index, info)) {
      out.push_back(info);
    }
  }
  return true;
}

bool idalib_dscu_load_image(std::int32_t image_index, dscu_image_info &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr || image_index < 0) {
    return false;
  }

  if (!ds->load_image(image_index)) {
    return false;
  }
  return fill_image_info(ds, image_index, out);
}

bool idalib_dscu_get_region_by_ea(std::uint64_t ea, dscu_region_info &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr) {
    return false;
  }

  region_info_t ri;
  if (!ds->get_region_by_ea(&ri, static_cast<ea_t>(ea))) {
    return false;
  }

  fill_region_info(ri, out);
  out.loaded = false;
  return true;
}

bool idalib_dscu_load_region(std::uint64_t ea, dscu_region_info &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr) {
    return false;
  }

  region_info_t ri;
  if (!ds->get_region_by_ea(&ri, static_cast<ea_t>(ea))) {
    return false;
  }

  fill_region_info(ri, out);

  bool ok = false;
  switch (ri.type) {
  case rt_image_entity:
    ok = ds->load_image(ri.image_index);
    out.loaded = ds->is_image_loaded(ri.image_index);
    break;
  case rt_island:
    ok = ds->load_island(ri.branch_island_number);
    out.loaded = ds->is_island_loaded(ri.branch_island_number);
    break;
  case rt_header:
    ok = true;
    out.loaded = true;
    break;
  case rt_mapping:
    ok = ds->load_branch_mapping(ri.start);
    out.loaded = ds->is_mapping_loaded(ri.start);
    break;
  case rt_unknown:
    ok = ds->load_unknown_region(ri.start);
    out.loaded = ds->is_unknown_region_loaded(ri.start);
    break;
  case rt_got:
    ok = ds->load_got(ri.start);
    out.loaded = ds->is_got_loaded(ri.start);
    break;
  case rt_cache_data:
    ok = ds->load_cache_data(ri.start);
    out.loaded = ds->is_cache_data_loaded(ri.start);
    break;
  default:
    ok = false;
    out.loaded = false;
    break;
  }

  return ok;
}

bool idalib_dscu_find_symbols(
    const char *needle,
    std::uint32_t flags,
    std::uint64_t max_count,
    rust::Vec<dscu_symbol_match> &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr || needle == nullptr || needle[0] == '\0') {
    return false;
  }

  symbol_match_vec_t matches;
  if (!ds->find_symbol(&matches, needle, flags, max_count_to_size(max_count))) {
    return false;
  }

  for (const auto &match : matches) {
    dscu_symbol_match item;
    item.symbol = string_view_to_rust(match.symbol);
    item.address = static_cast<std::uint64_t>(match.ea);
    item.image_index = static_cast<std::int32_t>(match.image_index);
    out.push_back(item);
  }
  return true;
}

bool idalib_dscu_find_strings(
    const char *needle,
    std::uint32_t flags,
    std::uint64_t max_count,
    rust::Vec<dscu_string_match> &out) {
  dscu_svc_t *ds = svc();
  if (ds == nullptr || needle == nullptr || needle[0] == '\0') {
    return false;
  }

  string_match_vec_t matches;
  if (!ds->find_string(&matches, needle, flags, max_count_to_size(max_count))) {
    return false;
  }

  for (const auto &match : matches) {
    dscu_string_match item;
    item.address = static_cast<std::uint64_t>(match.ea);
    item.image_index = static_cast<std::int32_t>(match.image_index);
    item.file_index = static_cast<std::uint64_t>(match.file_index);
    item.file_offset = static_cast<std::uint64_t>(match.file_offset);
    item.context = rust::String(match.context.c_str());
    out.push_back(item);
  }
  return true;
}
