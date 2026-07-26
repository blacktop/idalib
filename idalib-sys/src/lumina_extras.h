#pragma once

#include <cstdint>

struct lumina_pull_result;

bool idalib_lumina_pull(
    std::uint64_t ea,
    bool apply,
    bool force,
    lumina_pull_result &out);
