use crate::IDAError;

/// Result of executing a Python script via IDAPython.
#[derive(Debug, Clone)]
pub struct ScriptOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    /// JSON encoding of the script's trailing expression, when it has one
    /// that evaluates to something other than `None`. Always valid JSON of at
    /// most 1 MiB; a larger result fails the script instead.
    pub result_json: Option<String>,
    /// The value could not be encoded as strict JSON (unsupported type,
    /// non-finite float, circular reference, or an integer outside
    /// `i64::MIN..=u64::MAX` anywhere inside it), so `result_json` is the
    /// JSON string of its `repr()`.
    pub result_is_repr: bool,
}

impl ScriptOutput {
    pub(crate) fn from_ffi(r: idalib_sys::script::script_result) -> Self {
        let error = if r.error.is_empty() {
            None
        } else {
            Some(r.error)
        };
        let result_json = if r.result_json.is_empty() {
            None
        } else {
            Some(r.result_json)
        };
        Self {
            result_json,
            result_is_repr: r.result_is_repr,
            success: r.success,
            stdout: r.stdout_text,
            stderr: r.stderr_text,
            error,
        }
    }
}

/// Execute a Python snippet via the IDAPython extlang.
///
/// Captures stdout/stderr via StringIO redirect. The code runs in the
/// interpreter's globals, so names it defines persist for later calls, and a
/// trailing expression is returned as [`ScriptOutput::result_json`]. Returns an error if
/// the Python extlang is not available (plugin not loaded).
///
/// Must be called from the main thread (IDA requirement).
///
/// Note: does NOT call `prepare_library()` because the caller
/// (`IDB::run_python`) already holds the runtime mutex via `IDB._guard`.
/// Calling `prepare_library()` here would deadlock.
pub(crate) fn run_python(code: &str) -> Result<ScriptOutput, IDAError> {
    let mut out = idalib_sys::script::script_result::default();
    let available = unsafe { idalib_sys::script::idalib_run_python_snippet(code, &mut out) };
    if !available {
        return Err(IDAError::ffi_with(
            "IDAPython extlang not available (plugin may not be loaded)",
        ));
    }
    Ok(ScriptOutput::from_ffi(out))
}
