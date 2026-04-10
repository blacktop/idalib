//! # idalib
//!
//! idalib is a Rust library providing idiomatic bindings for the IDA SDK, enabling the development
//! of standalone analysis tools using IDA v9.x’s idalib.
//!
//! ## Usage
//!
//! To use idalib, add it as a dependency in your `Cargo.toml` and include a `build.rs` file in
//! your project to properly link against IDA:
//!
//! ```toml
//! [dependencies]
//! idalib = "0.7"
//!
//! [build-dependencies]
//! idalib-build = "0.7"
//! ```
//!
//! Here is a basic example of a `build.rs` file:
//!
//! ```rust,ignore
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     idalib_build::configure_linkage()?;
//!     Ok(())
//! }
//! ```
//!
//! This script uses the `idalib-build` crate to automatically configure the linkage against IDA.
//! If IDA is installed in a non-default location, ensure that `IDADIR` is set to point to your
//! installation directory, if you are linking against IDA's shared libraries, as opposed to the
//! stub libraries distributed with the SDK.
//!
//! ## Setting Environment Variables
//!
//! ### On Linux/macOS
//!
//! You can set the environment variables in your terminal session or add them to your shell
//! configuration file (e.g., `.bashrc`, `.zshrc`):
//!
//! ```sh,ignore
//! export IDADIR=/path/to/ida/installation
//! ```
//!
//! ### On Windows
//!
//! Set environment variables using Command Prompt, PowerShell, or System Properties.
//!
//! **Command Prompt:**
//! ```cmd
//! set IDADIR=C:\path\to\ida\installation
//! ```
//!
//! **PowerShell:**
//! ```powershell,ignore
//! $env:IDADIR = "C:\path\to\ida\installation"
//! ```
//!
//! **System Properties:**
//! Go to "Environment Variables" in System Properties and add `IDADIR`.
//!
//! ## Example
//!
//! Here's a simple example of how to use idalib:
//!
//! ```rust,ignore
//! use idalib::idb::IDB;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let idb = IDB::open("/path/to/binary")?;
//!     // Perform analysis...
//!     Ok(())
//! }
//! ```
//!
#![allow(clippy::needless_lifetimes)]

use std::marker::PhantomData;
use std::sync::{Mutex, MutexGuard, OnceLock};

pub mod bookmarks;
pub mod decompiler;
pub mod frame;
pub mod func;
pub mod idb;
pub mod insn;
pub mod license;
pub mod meta;
pub mod name;
pub mod plugin;
pub mod processor;
pub mod script;
pub mod segment;
pub mod strings;
pub mod types;
pub mod udt;
pub mod xref;

pub use ffi::IDAError;
pub use idalib_sys as ffi;
pub use idb::{IDB, IDBOpenOptions};
pub use license::{LicenseId, is_valid_license, license_id};

pub type Address = u64;
pub struct AddressFlags<'a> {
    flags: ffi::bytes::flags64_t,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> AddressFlags<'a> {
    pub(crate) fn new(flags: ffi::bytes::flags64_t) -> Self {
        Self {
            flags,
            _marker: PhantomData,
        }
    }

    pub fn is_code(&self) -> bool {
        unsafe { ffi::bytes::is_code(self.flags) }
    }

    pub fn is_data(&self) -> bool {
        unsafe { ffi::bytes::is_data(self.flags) }
    }
}

/// Compile-time IDA SDK version this crate was built against.
///
/// Derived from `IDA_SDK_VERSION` in `pro.h` (e.g. 930 → major 9, minor 3).
/// Compare with [`version()`] at runtime to detect mismatches before they
/// cause undefined behavior.
pub const SDK_VERSION: (i32, i32) = (9, 3);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IDAVersion {
    major: i32,
    minor: i32,
    build: i32,
}

impl IDAVersion {
    pub fn major(&self) -> i32 {
        self.major
    }

    pub fn minor(&self) -> i32 {
        self.minor
    }

    pub fn build(&self) -> i32 {
        self.build
    }
}

impl std::fmt::Display for IDAVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

static INIT: OnceLock<Result<Mutex<()>, String>> = OnceLock::new();

pub(crate) type IDARuntimeHandle = MutexGuard<'static, ()>;

pub fn force_batch_mode() {
    ffi::ida::set_batch_mode(true);
}

/// Initialize the IDA library. Must be called on the main thread.
///
/// Returns the library-wide mutex on success. The result is cached:
/// subsequent calls return the same outcome without re-initializing.
pub fn init_library() -> Result<&'static Mutex<()>, IDAError> {
    let result = INIT.get_or_init(|| match ffi::ida::init_library() {
        Ok(()) => {
            force_batch_mode();
            Ok(Mutex::new(()))
        }
        Err(e) => Err(format!("{e}")),
    });
    match result {
        Ok(m) => Ok(m),
        Err(msg) => Err(IDAError::ffi_with(msg.clone())),
    }
}

pub(crate) fn prepare_library() -> Result<IDARuntimeHandle, IDAError> {
    let mutex = init_library()?;
    Ok(mutex.lock().expect("IDA library mutex poisoned"))
}

pub fn enable_console_messages(enabled: bool) -> Result<(), IDAError> {
    init_library()?;
    ffi::ida::enable_console_messages(enabled);
    Ok(())
}

pub fn version() -> Result<IDAVersion, IDAError> {
    ffi::ida::library_version().map(|(major, minor, build)| IDAVersion {
        major,
        minor,
        build,
    })
}
