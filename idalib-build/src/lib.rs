use std::env;
use std::path::{Path, PathBuf};

/// Get the target OS from Cargo's environment (supports cross-compilation)
fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        // Fallback to host OS if not cross-compiling
        if cfg!(target_os = "linux") {
            "linux".to_string()
        } else if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "windows") {
            "windows".to_string()
        } else {
            panic!("unsupported host platform")
        }
    })
}

/// Get the target arch from Cargo's environment (supports cross-compilation)
fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| {
        // Fallback to host arch if not cross-compiling
        if cfg!(target_arch = "x86_64") {
            "x86_64".to_string()
        } else if cfg!(target_arch = "aarch64") {
            "aarch64".to_string()
        } else {
            panic!("unsupported host architecture")
        }
    })
}

/// Whether the SDK lacks stub libraries and a local IDA install is required
/// to link. The IDA 9.4 SDK ships stubs for all supported 64-bit platforms.
pub fn requires_local_ida_install() -> bool {
    false
}

fn link_path() -> PathBuf {
    let os = target_os();
    if os == "macos" {
        PathBuf::from("/Applications/IDA Professional 9.4.app/Contents/MacOS")
    } else if os == "linux" {
        PathBuf::from(env::var("HOME").unwrap()).join("ida-pro-9.4")
    } else if os == "windows" {
        PathBuf::from("C:\\Program Files\\IDA Professional 9.4")
    } else {
        panic!("unsupported platform: {}", os)
    }
}

pub fn idalib_sdk_paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    idalib_sdk_paths_with(true)
}

pub fn idalib_sdk_paths_with(check: bool) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let sdk_path = PathBuf::from(env!("IDALIB_SDK"));
    let pro_h = sdk_path.join("include").join("pro.h");

    if check && !pro_h.exists() {
        panic!("`{}` does not exist; SDK is not usable", pro_h.display());
    }

    let os = target_os();
    let arch = target_arch();

    let (stubs_path, idalib, ida) = if os == "linux" {
        let path = if arch == "aarch64" {
            sdk_path.join("lib/arm64_linux_64")
        } else {
            sdk_path.join("lib/x64_linux_64")
        };
        let idalib = path.join("libidalib.so");
        let ida = path.join("libida.so");
        (path, idalib, ida)
    } else if os == "macos" {
        let path = if arch == "x86_64" {
            sdk_path.join("lib/x64_mac_64")
        } else {
            sdk_path.join("lib/arm64_mac_64")
        };
        let idalib = path.join("libidalib.dylib");
        let ida = path.join("libida.dylib");
        (path, idalib, ida)
    } else if os == "windows" {
        let path = if arch == "aarch64" {
            sdk_path.join("lib/arm64_win_64")
        } else {
            sdk_path.join("lib/x64_win_64")
        };
        let idalib = path.join("idalib.lib");
        let ida = path.join("ida.lib");
        (path, idalib, ida)
    } else {
        panic!("unsupported platform: {}", os);
    };

    (sdk_path, stubs_path, idalib, ida)
}

pub fn idalib_install_paths() -> (PathBuf, PathBuf, PathBuf) {
    idalib_install_paths_with(true)
}

pub fn idalib_install_paths_with(check: bool) -> (PathBuf, PathBuf, PathBuf) {
    let path = env::var("IDADIR").map_or_else(|_| link_path(), PathBuf::from);
    let os = target_os();

    let (idalib, ida) = if os == "linux" {
        (path.join("libidalib.so"), path.join("libida.so"))
    } else if os == "macos" {
        (path.join("libidalib.dylib"), path.join("libida.dylib"))
    } else if os == "windows" {
        (path.join("idalib.dll"), path.join("ida.dll"))
    } else {
        panic!("unsupported platform: {}", os)
    };

    // Skip existence check when cross-compiling (the libs won't exist on the host)
    let is_cross_compiling = env::var("CARGO_CFG_TARGET_OS").is_ok()
        && env::var("CARGO_CFG_TARGET_OS").unwrap() != std::env::consts::OS;

    if check && !is_cross_compiling && !idalib.exists() {
        panic!(
            "`{}` does not exist; cannot find a compatible IDA Pro installation",
            idalib.display()
        );
    }

    (path, idalib, ida)
}

pub fn idalib_library_paths() -> (PathBuf, PathBuf) {
    idalib_library_paths_with(true)
}

pub fn idalib_library_paths_with(check: bool) -> (PathBuf, PathBuf) {
    let (_, idalib, ida) = idalib_install_paths_with(check);
    (idalib, ida)
}

fn configure_linkage_aux(path: &Path) {
    let os = target_os();
    println!("cargo::rustc-link-search=native={}", path.display());
    if os == "windows" {
        // .lib
        println!("cargo::rustc-link-lib=static=ida");
        println!("cargo::rustc-link-lib=static=idalib");
    } else {
        // .dylib/.so
        println!("cargo::rustc-link-lib=dylib=ida");
        println!("cargo::rustc-link-lib=dylib=idalib");
    }
}

pub fn configure_idalib_linkage() {
    let (install_path, _, _) = idalib_install_paths();
    configure_linkage_aux(&install_path);
}

pub fn configure_idasdk_linkage() {
    let (_, stubs_path, _, _) = idalib_sdk_paths();
    configure_linkage_aux(&stubs_path);

    if target_os() == "windows" {
        // FIXME: this seems to be required otherwise we report missing symbols and bail during
        // linking (seems to be due to autocxx)...
        println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
    }
}

pub fn configure_linkage() -> anyhow::Result<()> {
    let os = target_os();

    if os == "windows" {
        configure_idasdk_linkage();
        return Ok(());
    }

    let (install_path, _, _) = idalib_install_paths_with(false);
    let (_, stub_path, _, _) = idalib_sdk_paths();

    println!(
        "cargo::rustc-link-arg=-Wl,-rpath,{}",
        install_path.display()
    );
    configure_linkage_aux(&stub_path);

    Ok(())
}
