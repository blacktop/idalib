use std::ffi::CString;

use crate::{IDAError, ffi, init_library};

/// Write a boolean value to IDA's active registry.
///
/// IDAUSR isolation, when configured by the caller before library
/// initialization, determines which registry is modified.
pub fn set_bool(name: &str, value: bool) -> Result<(), IDAError> {
    let name = CString::new(name).map_err(IDAError::ffi)?;
    init_library()?;

    // SAFETY: `name` is a valid NUL-terminated string that remains alive for
    // the call. The SDK documents registry writes as thread-safe.
    unsafe {
        ffi::registry::idalib_reg_write_bool(name.as_ptr(), value);
    }
    Ok(())
}

/// Read a boolean value from IDA's active registry.
pub fn get_bool(name: &str, default_value: bool) -> Result<bool, IDAError> {
    let name = CString::new(name).map_err(IDAError::ffi)?;
    init_library()?;

    // SAFETY: `name` is a valid NUL-terminated string that remains alive for
    // the call. The SDK documents registry reads as thread-safe.
    Ok(unsafe { ffi::registry::idalib_reg_read_bool(name.as_ptr(), default_value) })
}

#[cfg(test)]
mod tests {
    use crate::registry::{get_bool, set_bool};

    #[test]
    fn registry_names_reject_interior_nuls_before_initializing_ida() {
        assert!(set_bool("invalid\0name", false).is_err());
        assert!(get_bool("invalid\0name", false).is_err());
    }
}
