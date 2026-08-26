use crate::ffi::debugger::{
    idalib_debugger_attach, idalib_debugger_detach, idalib_debugger_launch, idalib_debugger_load,
    idalib_debugger_modules, idalib_debugger_process_state, idalib_debugger_terminate,
};
use crate::{Address, IDAError, IDB};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebuggerModule {
    pub path: String,
    pub base: Address,
    pub size: u64,
    pub rebase_to: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerProcessState {
    Suspended,
    NoProcess,
    Running,
    Unknown(i32),
}

impl From<i32> for DebuggerProcessState {
    fn from(value: i32) -> Self {
        match value {
            -1 => Self::Suspended,
            0 => Self::NoProcess,
            1 => Self::Running,
            value => Self::Unknown(value),
        }
    }
}

fn operation_result(ok: bool, error: String) -> Result<(), IDAError> {
    if ok {
        Ok(())
    } else if error.is_empty() {
        Err(IDAError::ffi_with("IDA debugger operation failed"))
    } else {
        Err(IDAError::ffi_with(error))
    }
}

fn timeout_seconds(timeout_seconds: u32) -> Result<i32, IDAError> {
    i32::try_from(timeout_seconds)
        .map_err(|_| IDAError::ffi_with("debugger timeout exceeds the IDA SDK range"))
}

impl IDB {
    pub fn debugger_load(
        &self,
        name: &str,
        use_remote: bool,
        host: Option<&str>,
        port: Option<u16>,
    ) -> Result<(), IDAError> {
        let mut error = String::new();
        let ok = unsafe {
            idalib_debugger_load(
                name,
                use_remote,
                host.unwrap_or_default(),
                port.map(i32::from).unwrap_or(-1),
                &mut error,
            )
        };
        operation_result(ok, error)
    }

    pub fn debugger_launch(
        &self,
        path: &str,
        args: Option<&str>,
        start_directory: Option<&str>,
        timeout_seconds_value: u32,
    ) -> Result<i32, IDAError> {
        let mut event_code = 0;
        let mut error = String::new();
        let ok = unsafe {
            idalib_debugger_launch(
                path,
                args.unwrap_or_default(),
                start_directory.unwrap_or_default(),
                timeout_seconds(timeout_seconds_value)?,
                &mut event_code,
                &mut error,
            )
        };
        operation_result(ok, error)?;
        Ok(event_code)
    }

    pub fn debugger_attach(&self, pid: u32, timeout_seconds_value: u32) -> Result<i32, IDAError> {
        let pid = i32::try_from(pid)
            .map_err(|_| IDAError::ffi_with("debug process ID exceeds the IDA SDK range"))?;
        let mut event_code = 0;
        let mut error = String::new();
        let ok = unsafe {
            idalib_debugger_attach(
                pid,
                timeout_seconds(timeout_seconds_value)?,
                &mut event_code,
                &mut error,
            )
        };
        operation_result(ok, error)?;
        Ok(event_code)
    }

    pub fn debugger_modules(&self) -> Result<Vec<DebuggerModule>, IDAError> {
        let mut modules = Vec::new();
        let mut error = String::new();
        let ok = unsafe { idalib_debugger_modules(&mut modules, &mut error) };
        operation_result(ok, error)?;
        Ok(modules
            .into_iter()
            .map(|module| DebuggerModule {
                path: module.path,
                base: module.base,
                size: module.size,
                rebase_to: module.rebase_to,
            })
            .collect())
    }

    pub fn debugger_detach(&self, timeout_seconds_value: u32) -> Result<i32, IDAError> {
        let mut event_code = 0;
        let mut error = String::new();
        let ok = unsafe {
            idalib_debugger_detach(
                timeout_seconds(timeout_seconds_value)?,
                &mut event_code,
                &mut error,
            )
        };
        operation_result(ok, error)?;
        Ok(event_code)
    }

    pub fn debugger_terminate(&self, timeout_seconds_value: u32) -> Result<i32, IDAError> {
        let mut event_code = 0;
        let mut error = String::new();
        let ok = unsafe {
            idalib_debugger_terminate(
                timeout_seconds(timeout_seconds_value)?,
                &mut event_code,
                &mut error,
            )
        };
        operation_result(ok, error)?;
        Ok(event_code)
    }

    pub fn debugger_process_state(&self) -> DebuggerProcessState {
        DebuggerProcessState::from(unsafe { idalib_debugger_process_state() })
    }
}
