#pragma once

#include <cstdint>

#include "cxx.h"

struct dscu_image_info;
struct dscu_region_info;
struct dscu_symbol_match;
struct dscu_string_match;

bool idalib_dscu_available();
rust::String idalib_dscu_input_file_path();
std::int32_t idalib_dscu_images_count();
std::int32_t idalib_dscu_get_image_index(const char *name);
bool idalib_dscu_get_image_info(std::int32_t image_index, dscu_image_info &out);
bool idalib_dscu_get_images(rust::Vec<dscu_image_info> &out);
bool idalib_dscu_get_image_dependencies(
    std::int32_t image_index,
    std::int32_t depth,
    rust::Vec<dscu_image_info> &out);
bool idalib_dscu_load_image(std::int32_t image_index, dscu_image_info &out);
bool idalib_dscu_get_region_by_ea(std::uint64_t ea, dscu_region_info &out);
bool idalib_dscu_load_region(std::uint64_t ea, dscu_region_info &out);
bool idalib_dscu_find_symbols(
    const char *needle,
    std::uint32_t flags,
    std::uint64_t max_count,
    rust::Vec<dscu_symbol_match> &out);
bool idalib_dscu_find_strings(
    const char *needle,
    std::uint32_t flags,
    std::uint64_t max_count,
    rust::Vec<dscu_string_match> &out);
