#include "cxxgen1.h"
#include "expr.hpp"

// Maximum captured output size (1 MB) to prevent flooding.
static constexpr size_t MAX_OUTPUT_SIZE = 1024 * 1024;

static rust::String truncate_output(const char *s) {
  if (!s || !*s) return rust::String();
  size_t len = strlen(s);
  if (len > MAX_OUTPUT_SIZE) {
    // Back up to nearest valid UTF-8 character boundary so the
    // resulting string is valid UTF-8 (required by rust::String).
    size_t truncate_at = MAX_OUTPUT_SIZE;
    while (truncate_at > 0 && (s[truncate_at] & 0xC0) == 0x80) {
      truncate_at--;
    }
    std::string truncated(s, truncate_at);
    truncated += "\n... [truncated at 1MB]";
    return rust::String(truncated);
  }
  return rust::String(s, len);
}

bool idalib_run_python_snippet(rust::Str code, script_result &out) {
  out.success = false;
  out.stdout_text = rust::String();
  out.stderr_text = rust::String();
  out.error = rust::String();
  out.result_json = rust::String();
  out.result_is_repr = false;

  // Find the Python extlang
  extlang_object_t py = find_extlang_by_name("Python");
  if (!py) {
    out.error = rust::String("IDAPython extlang not available (plugin may not be loaded)");
    return false;
  }

  // Build a wrapper that redirects stdout/stderr via StringIO,
  // executes the user code in the interpreter's globals (so names persist
  // between calls), evaluates a trailing expression as the result, then
  // stores captured output in globals that we can retrieve with eval_expr.
  // The result is strict JSON whose integers fit the reader's native
  // i64/u64 range; anything else falls back to repr() so no value is
  // silently rounded.
  std::string user_code(code.data(), code.length());

  // Escape the user code for embedding in a triple-quoted string.
  // We use a unique delimiter to avoid collisions.
  std::string wrapper =
    "import sys as _mcp_sys\n"
    "from io import StringIO as _mcp_StringIO\n"
    "_mcp_out = _mcp_StringIO()\n"
    "_mcp_err = _mcp_StringIO()\n"
    "_mcp_old_stdout = _mcp_sys.stdout\n"
    "_mcp_old_stderr = _mcp_sys.stderr\n"
    "_mcp_sys.stdout = _mcp_out\n"
    "_mcp_sys.stderr = _mcp_err\n"
    "_mcp_exec_error = ''\n"
    "_mcp_result_json = ''\n"
    "_mcp_result_is_repr = 0\n"
    "def _mcp_json_exact(_mcp_v):\n"
    "    if isinstance(_mcp_v, bool):\n"
    "        return True\n"
    "    if isinstance(_mcp_v, int):\n"
    "        return -(1 << 63) <= _mcp_v <= (1 << 64) - 1\n"
    "    if isinstance(_mcp_v, (list, tuple)):\n"
    "        return all(_mcp_json_exact(_mcp_item) for _mcp_item in _mcp_v)\n"
    "    if isinstance(_mcp_v, dict):\n"
    "        return all(_mcp_json_exact(_mcp_item) for _mcp_item in _mcp_v.values())\n"
    "    return True\n"
    "try:\n"
    "    import ast as _mcp_ast, json as _mcp_json\n"
    "    _mcp_tree = _mcp_ast.parse(_mcp_code_input, '<run_script>')\n"
    "    _mcp_last = None\n"
    "    if _mcp_tree.body and isinstance(_mcp_tree.body[-1], _mcp_ast.Expr):\n"
    "        _mcp_last = _mcp_ast.Expression(_mcp_tree.body.pop().value)\n"
    "    exec(compile(_mcp_tree, '<run_script>', 'exec'), globals())\n"
    "    if _mcp_last is not None:\n"
    "        _mcp_value = eval(compile(_mcp_last, '<run_script>', 'eval'), globals())\n"
    "        if _mcp_value is not None:\n"
    "            try:\n"
    "                _mcp_encoded = _mcp_json.dumps(_mcp_value, allow_nan=False)\n"
    "                if not _mcp_json_exact(_mcp_value):\n"
    "                    raise TypeError('integer outside the 64-bit range')\n"
    "            except (TypeError, ValueError):\n"
    "                _mcp_encoded = _mcp_json.dumps(repr(_mcp_value))\n"
    "                _mcp_result_is_repr = 1\n"
    "            if len(_mcp_encoded) > 1048576:\n"
    "                _mcp_result_is_repr = 0\n"
    "                raise ValueError(\n"
    "                    'script result is %d bytes of JSON, over the 1 MiB limit; '\n"
    "                    'return a smaller value' % len(_mcp_encoded))\n"
    "            _mcp_result_json = _mcp_encoded\n"
    "except Exception as _mcp_e:\n"
    "    import traceback as _mcp_traceback\n"
    "    _mcp_traceback.print_exc(file=_mcp_err)\n"
    "    _mcp_exec_error = type(_mcp_e).__name__ + ': ' + str(_mcp_e)\n"
    "finally:\n"
    "    _mcp_sys.stdout = _mcp_old_stdout\n"
    "    _mcp_sys.stderr = _mcp_old_stderr\n"
    "_mcp_captured_stdout = _mcp_out.getvalue()\n"
    "_mcp_captured_stderr = _mcp_err.getvalue()\n";

  // First, set the user code as a Python variable so we don't need
  // to escape it for embedding.
  // Use compile() + exec() to set the code string safely.
  std::string set_code = "_mcp_code_input = compile(";

  // Build a repr-like escaped string for the code.
  // We use the Python extlang's eval_expr to set the variable.
  // Simpler approach: use eval_snippet to set the variable directly.
  // We need to be careful with escaping. Use raw triple-quotes.

  // Strategy: eval_snippet to set _mcp_code_input via a safe method,
  // then eval_snippet to run the wrapper.
  // Use base64 to avoid all escaping issues.
  std::string setup =
    "import base64 as _mcp_b64\n"
    "_mcp_code_input = _mcp_b64.b64decode('";

  // Base64 encode the user code
  // Simple base64 implementation for the C++ side
  static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string b64;
  size_t i = 0;
  size_t code_len = user_code.length();
  const unsigned char *data = reinterpret_cast<const unsigned char *>(user_code.data());
  for (i = 0; i + 2 < code_len; i += 3) {
    b64 += b64_table[(data[i] >> 2) & 0x3F];
    b64 += b64_table[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
    b64 += b64_table[((data[i+1] & 0xF) << 2) | ((data[i+2] >> 6) & 0x3)];
    b64 += b64_table[data[i+2] & 0x3F];
  }
  if (i < code_len) {
    b64 += b64_table[(data[i] >> 2) & 0x3F];
    if (i + 1 < code_len) {
      b64 += b64_table[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
      b64 += b64_table[((data[i+1] & 0xF) << 2)];
    } else {
      b64 += b64_table[((data[i] & 0x3) << 4)];
      b64 += '=';
    }
    b64 += '=';
  }

  setup += b64;
  setup += "').decode('utf-8')\n";

  // Step 1: Set the code variable
  qstring errbuf;
  if (!py->eval_snippet(setup.c_str(), &errbuf)) {
    out.error = rust::String(std::string("failed to set code variable: ") +
                             (errbuf.empty() ? "unknown error" : errbuf.c_str()));
    return true;  // extlang is available, but execution failed
  }

  // Step 2: Run the wrapper that executes the code with stdout/stderr capture
  errbuf.qclear();
  if (!py->eval_snippet(wrapper.c_str(), &errbuf)) {
    out.error = rust::String(std::string("failed to execute wrapper: ") +
                             (errbuf.empty() ? "unknown error" : errbuf.c_str()));
    return true;
  }

  // Step 3: Retrieve captured stdout
  idc_value_t rv;
  errbuf.qclear();
  if (py->eval_expr(&rv, BADADDR, "_mcp_captured_stdout", &errbuf)) {
    if (rv.vtype == VT_STR) {
      out.stdout_text = truncate_output(rv.c_str());
    }
  }

  // Step 4: Retrieve captured stderr
  errbuf.qclear();
  if (py->eval_expr(&rv, BADADDR, "_mcp_captured_stderr", &errbuf)) {
    if (rv.vtype == VT_STR) {
      out.stderr_text = truncate_output(rv.c_str());
    }
  }

  // Step 5: Retrieve exec error
  errbuf.qclear();
  if (py->eval_expr(&rv, BADADDR, "_mcp_exec_error", &errbuf)) {
    if (rv.vtype == VT_STR && rv.c_str()[0] != '\0') {
      out.error = truncate_output(rv.c_str());
      out.success = false;
    } else {
      out.success = true;
    }
  } else {
    // Could not retrieve error status; assume success if we got here
    out.success = true;
  }

  // Step 6: Retrieve the trailing-expression result. The wrapper bounds its
  // size, so it is copied whole: truncating would leave invalid JSON.
  errbuf.qclear();
  if (py->eval_expr(&rv, BADADDR, "_mcp_result_json", &errbuf)) {
    if (rv.vtype == VT_STR) {
      out.result_json = rust::String(rv.c_str());
    }
  }
  errbuf.qclear();
  if (py->eval_expr(&rv, BADADDR, "_mcp_result_is_repr", &errbuf)) {
    out.result_is_repr = (rv.vtype == VT_LONG && rv.num != 0)
                         || (rv.vtype == VT_INT64 && rv.i64 != 0);
  }

  // Step 7: Clean up temporary variables (wrapped in try/except in
  // case earlier steps failed before all variables were created).
  py->eval_snippet(
    "try:\n"
    "    del _mcp_code_input, _mcp_out, _mcp_err, _mcp_old_stdout, _mcp_old_stderr, "
    "_mcp_captured_stdout, _mcp_captured_stderr, _mcp_exec_error, _mcp_sys, "
    "_mcp_StringIO, _mcp_b64, _mcp_result_json, _mcp_result_is_repr\n"
    "except NameError:\n"
    "    pass\n"
    "for _mcp_name in ('_mcp_ast', '_mcp_json', '_mcp_tree', '_mcp_last', '_mcp_value',\n"
    "                  '_mcp_encoded', '_mcp_json_exact',\n"
    "                  '_mcp_e', '_mcp_traceback'):\n"
    "    globals().pop(_mcp_name, None)\n"
    "del _mcp_name\n",
    &errbuf);

  return true;
}
