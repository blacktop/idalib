use crate::IDAError;

/// Result of executing a Python script via IDAPython.
#[derive(Debug, Clone)]
pub struct ScriptOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

impl ScriptOutput {
    pub(crate) fn from_ffi(r: idalib_sys::script::script_result) -> Self {
        let error = if r.error.is_empty() {
            None
        } else {
            Some(r.error)
        };
        Self {
            success: r.success,
            stdout: r.stdout_text,
            stderr: r.stderr_text,
            error,
        }
    }
}

/// Execute a Python snippet via the IDAPython extlang.
///
/// Captures stdout/stderr via StringIO redirect. Returns an error if
/// the Python extlang is not available (plugin not loaded).
///
/// Must be called from the main thread (IDA requirement).
pub fn run_python(code: &str) -> Result<ScriptOutput, IDAError> {
    let _guard = crate::prepare_library();
    let mut out = idalib_sys::script::script_result::default();
    let available = unsafe { idalib_sys::script::idalib_run_python_snippet(code, &mut out) };
    if !available {
        return Err(IDAError::ffi_with(
            "IDAPython extlang not available (plugin may not be loaded)",
        ));
    }
    Ok(ScriptOutput::from_ffi(out))
}
