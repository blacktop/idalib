#include "cxxgen1.h"

#include "debugger_extras.h"

#include <algorithm>
#include <chrono>
#include <limits>
#include <string>

namespace {

std::string to_string(rust::Str value) {
  return std::string(value.data(), value.size());
}

const char *nullable(const std::string &value) {
  return value.empty() ? nullptr : value.c_str();
}

bool wait_for_debug_event(std::int32_t wait_flags, std::int32_t timeout_seconds,
                          std::int32_t &event_code, rust::String &error) {
  if (timeout_seconds < 0) {
    error = rust::String("debugger timeout must be non-negative");
    return false;
  }
  const int result = static_cast<int>(
      wait_for_next_event(wait_flags | WFNE_SILENT, timeout_seconds));
  event_code = result;
  if (result > 0) {
    return true;
  }
  if (result == DEC_TIMEOUT) {
    error = rust::String("timed out waiting for debugger event");
  } else if (result == DEC_NOTASK) {
    error = rust::String("debugger reported no active process");
  } else {
    error = rust::String("debugger event wait failed");
  }
  return false;
}

enum class terminal_wait_outcome {
  matched,
  pending,
  timeout,
  no_task,
  failed,
};

constexpr terminal_wait_outcome
classify_terminal_wait(int result, int terminal_event, int process_state) {
  if (result == terminal_event) {
    return terminal_wait_outcome::matched;
  }
  if (result > 0) {
    return terminal_wait_outcome::pending;
  }
  if (result == DEC_TIMEOUT) {
    return terminal_wait_outcome::timeout;
  }
  if (result == DEC_NOTASK || process_state == DSTATE_NOTASK) {
    return terminal_wait_outcome::no_task;
  }
  return terminal_wait_outcome::failed;
}

static_assert(classify_terminal_wait(DEC_ERROR, PROCESS_EXITED,
                                     DSTATE_NOTASK) ==
              terminal_wait_outcome::no_task);
static_assert(classify_terminal_wait(PROCESS_EXITED, PROCESS_EXITED,
                                     DSTATE_NOTASK) ==
              terminal_wait_outcome::matched);
static_assert(classify_terminal_wait(THREAD_EXITED, PROCESS_EXITED,
                                     DSTATE_NOTASK) ==
              terminal_wait_outcome::pending);

bool wait_for_terminal_debug_event(std::int32_t terminal_event,
                                   std::int32_t timeout_seconds,
                                   std::int32_t &event_code,
                                   rust::String &error) {
  if (timeout_seconds < 0) {
    error = rust::String("debugger timeout must be non-negative");
    return false;
  }

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
  bool first_wait = true;
  for (;;) {
    const auto now = std::chrono::steady_clock::now();
    if (!first_wait && now >= deadline) {
      error = rust::String("timed out waiting for debugger teardown");
      return false;
    }

    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
            .count();
    const auto rounded_seconds = remaining <= 0 ? 0 : (remaining + 999) / 1000;
    const auto bounded_seconds = std::min<std::int64_t>(
        rounded_seconds, std::numeric_limits<std::int32_t>::max());
    const int result = static_cast<int>(wait_for_next_event(
        WFNE_ANY | WFNE_SILENT, static_cast<int>(bounded_seconds)));
    first_wait = false;
    event_code = result;

    switch (
        classify_terminal_wait(result, terminal_event, get_process_state())) {
    case terminal_wait_outcome::matched:
      return true;
    case terminal_wait_outcome::pending:
      continue;
    case terminal_wait_outcome::timeout:
      error = rust::String("timed out waiting for debugger teardown");
      return false;
    case terminal_wait_outcome::no_task:
      error = rust::String("debugger became inactive before the requested "
                           "terminal event was observed");
      return false;
    case terminal_wait_outcome::failed:
      error = rust::String("debugger teardown event wait failed");
      return false;
    }
  }
}

} // namespace

bool idalib_debugger_load(rust::Str name, bool use_remote, rust::Str host,
                          std::int32_t port, rust::String &error) {
  const std::string debugger_name = to_string(name);
  const std::string remote_host = to_string(host);
  if (debugger_name.empty()) {
    error = rust::String("debugger name must not be empty");
    return false;
  }
  if (use_remote && remote_host.empty()) {
    error = rust::String("remote debugger host must not be empty");
    return false;
  }
  if (!load_debugger(debugger_name.c_str(), use_remote)) {
    error = rust::String("IDA could not load the requested debugger backend");
    return false;
  }
  if (use_remote) {
    set_remote_debugger(remote_host.c_str(), nullptr, port);
  }
  const uint required_options = DOPT_ENTRY_BPT | DOPT_LIB_MSGS;
  const uint previous_options = set_debugger_options(required_options);
  set_debugger_options(previous_options | required_options);
  return true;
}

bool idalib_debugger_launch(rust::Str path, rust::Str args,
                            rust::Str start_directory,
                            std::int32_t timeout_seconds,
                            std::int32_t &event_code, rust::String &error) {
  const std::string executable = to_string(path);
  const std::string arguments = to_string(args);
  const std::string directory = to_string(start_directory);
  if (executable.empty()) {
    error = rust::String("debug executable path must not be empty");
    return false;
  }
  const int result = start_process(executable.c_str(), nullable(arguments),
                                   nullable(directory));
  if (result != 1) {
    error = rust::String(result == 0 ? "debug launch was cancelled"
                                     : "debugger could not launch process");
    event_code = result;
    return false;
  }
  return wait_for_debug_event(WFNE_SUSP, timeout_seconds, event_code, error);
}

bool idalib_debugger_attach(std::int32_t pid, std::int32_t timeout_seconds,
                            std::int32_t &event_code, rust::String &error) {
  if (pid <= 0) {
    error = rust::String("debug process ID must be positive");
    return false;
  }
  const int result = attach_process(static_cast<pid_t>(pid), -1);
  if (result != 1) {
    error = rust::String("debugger could not attach to process");
    event_code = result;
    return false;
  }
  return wait_for_debug_event(WFNE_SUSP, timeout_seconds, event_code, error);
}

bool idalib_debugger_modules(rust::Vec<debugger_module_info> &modules,
                             rust::String &error) {
  if (get_process_state() == DSTATE_NOTASK) {
    error = rust::String("no process is being debugged");
    return false;
  }

  modinfo_t module;
  for (bool found = get_first_module(&module); found;
       found = get_next_module(&module)) {
    debugger_module_info info;
    info.path = rust::String(module.name.c_str());
    info.base = static_cast<std::uint64_t>(module.base);
    info.size = static_cast<std::uint64_t>(module.size);
    info.rebase_to = static_cast<std::uint64_t>(module.rebase_to);
    modules.push_back(std::move(info));
  }
  return true;
}

bool idalib_debugger_detach(std::int32_t timeout_seconds,
                            std::int32_t &event_code, rust::String &error) {
  if (!detach_process()) {
    error = rust::String("debugger could not detach from process");
    return false;
  }
  return wait_for_terminal_debug_event(PROCESS_DETACHED, timeout_seconds,
                                       event_code, error);
}

bool idalib_debugger_terminate(std::int32_t timeout_seconds,
                               std::int32_t &event_code, rust::String &error) {
  if (!exit_process()) {
    error = rust::String("debugger could not terminate process");
    return false;
  }
  return wait_for_terminal_debug_event(PROCESS_EXITED, timeout_seconds,
                                       event_code, error);
}

std::int32_t idalib_debugger_process_state() { return get_process_state(); }
