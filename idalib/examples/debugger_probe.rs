use idalib::{IDBOpenOptions, init_library};

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
    #[cfg(target_os = "macos")]
    database.debugger_load("arm_mac", true, Some("127.0.0.1"), Some(23946))?;
    #[cfg(target_os = "linux")]
    database.debugger_load("linux", false, None, None)?;
    #[cfg(target_os = "windows")]
    database.debugger_load("win32", false, None, None)?;
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
