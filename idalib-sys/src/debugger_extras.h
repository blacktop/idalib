#pragma once

#include <cstdint>

#include "cxx.h"

struct debugger_module_info;

bool idalib_debugger_load(rust::Str name, bool use_remote, rust::Str host,
                          std::int32_t port, rust::String &error);
bool idalib_debugger_launch(rust::Str path, rust::Str args,
                            rust::Str start_directory,
                            std::int32_t timeout_seconds,
                            std::int32_t &event_code, rust::String &error);
bool idalib_debugger_attach(std::int32_t pid, std::int32_t timeout_seconds,
                            std::int32_t &event_code, rust::String &error);
bool idalib_debugger_modules(rust::Vec<debugger_module_info> &modules,
                             rust::String &error);
bool idalib_debugger_detach(std::int32_t timeout_seconds,
                            std::int32_t &event_code, rust::String &error);
bool idalib_debugger_terminate(std::int32_t timeout_seconds,
                               std::int32_t &event_code, rust::String &error);
std::int32_t idalib_debugger_process_state();
