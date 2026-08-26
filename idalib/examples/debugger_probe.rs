use idalib::{IDBOpenOptions, init_library};

fn debugger_backend(os: &str, arch: &str) -> Option<(&'static str, bool)> {
    match (os, arch) {
        ("macos", "aarch64") => Some(("arm_mac", true)),
        ("macos", "x86_64") => Some(("mac", true)),
        ("linux", "aarch64") => Some(("armlinux", false)),
        ("linux", "x86_64") => Some(("linux", false)),
        ("windows", "aarch64" | "x86_64") => Some(("win32", false)),
        _ => None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let idb = args
        .next()
        .ok_or("usage: debugger_probe <idb> <executable>")?;
    let executable = args
        .next()
        .ok_or("usage: debugger_probe <idb> <executable>")?;

    init_library()?;
    let mut options = IDBOpenOptions::new();
    options.save(false).auto_analyse(false);
    let idb_exists = std::path::Path::new(&idb).exists();
    if !idb_exists {
        options.idb(&idb);
    }
    let database = options.open(if idb_exists { &idb } else { &executable })?;
    let (backend, use_remote) = debugger_backend(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or("no default IDA debugger backend for this host architecture")?;
    let host = use_remote.then_some("127.0.0.1");
    let port = use_remote.then_some(23946);
    database.debugger_load(backend, use_remote, host, port)?;
    let event_code = database.debugger_launch(&executable, None, None, 30)?;
    let modules = database.debugger_modules()?;
    println!(
        "event_code={event_code} state={:?}",
        database.debugger_process_state()
    );
    for module in &modules {
        println!(
            "{:#x}-{:#x} {}",
            module.base,
            module.base.saturating_add(module.size),
            module.path
        );
    }
    database.debugger_terminate(10)?;
    if modules.is_empty() {
        return Err("debugger reported no loaded modules".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::debugger_backend;

    #[test]
    fn debugger_backends_follow_host_architecture() {
        assert_eq!(
            debugger_backend("macos", "aarch64"),
            Some(("arm_mac", true))
        );
        assert_eq!(debugger_backend("macos", "x86_64"), Some(("mac", true)));
        assert_eq!(
            debugger_backend("linux", "aarch64"),
            Some(("armlinux", false))
        );
        assert_eq!(debugger_backend("linux", "x86_64"), Some(("linux", false)));
        assert_eq!(
            debugger_backend("windows", "aarch64"),
            Some(("win32", false))
        );
        assert_eq!(debugger_backend("freebsd", "x86_64"), None);
    }
}
