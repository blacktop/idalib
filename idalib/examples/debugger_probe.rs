use idalib::meta::FileType;
use idalib::{IDB, IDBOpenOptions, init_library};

const USAGE: &str = "usage: debugger_probe <idb> <executable> local\n       debugger_probe <idb> <executable> remote <host> <port>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetArchitecture {
    Arm,
    Aarch64,
    X86,
    X86_64,
}

#[derive(Debug, PartialEq, Eq)]
struct DebuggerConnection {
    use_remote: bool,
    host: Option<String>,
    port: Option<u16>,
}

fn parse_connection(args: &[String]) -> Result<DebuggerConnection, String> {
    match args {
        [mode] if mode == "local" => Ok(DebuggerConnection {
            use_remote: false,
            host: None,
            port: None,
        }),
        [mode, host, port] if mode == "remote" && !host.is_empty() => {
            let port = port
                .parse::<u16>()
                .map_err(|error| format!("invalid remote debugger port: {error}"))?;
            if port == 0 {
                return Err("remote debugger port must be non-zero".to_string());
            }
            Ok(DebuggerConnection {
                use_remote: true,
                host: Some(host.clone()),
                port: Some(port),
            })
        }
        _ => Err(USAGE.to_string()),
    }
}

fn target_architecture(database: &IDB) -> Result<TargetArchitecture, String> {
    let family = database.processor().family();
    let is_64bit = database.meta().is_64bit();
    if family.is_arm() {
        Ok(if is_64bit {
            TargetArchitecture::Aarch64
        } else {
            TargetArchitecture::Arm
        })
    } else if family.is_386() {
        Ok(if is_64bit {
            TargetArchitecture::X86_64
        } else {
            TargetArchitecture::X86
        })
    } else {
        Err(format!(
            "no debugger probe mapping for target processor {}",
            database.processor().short_name()
        ))
    }
}

fn debugger_backend(
    file_type: FileType,
    architecture: TargetArchitecture,
    use_remote: bool,
) -> Result<&'static str, String> {
    match (file_type, architecture, use_remote) {
        (FileType::MACHO, TargetArchitecture::Aarch64, _) => Ok("arm_mac"),
        (FileType::MACHO, TargetArchitecture::X86 | TargetArchitecture::X86_64, _) => Ok("mac"),
        (FileType::ELF, TargetArchitecture::Arm | TargetArchitecture::Aarch64, true) => {
            Ok("armlinux")
        }
        (FileType::ELF, TargetArchitecture::Arm | TargetArchitecture::Aarch64, false) => Err(
            "the armlinux debugger backend is remote-only; use remote <host> <port>".to_string(),
        ),
        (FileType::ELF, TargetArchitecture::X86 | TargetArchitecture::X86_64, _) => Ok("linux"),
        (FileType::PE, TargetArchitecture::X86 | TargetArchitecture::X86_64, _) => Ok("win32"),
        (FileType::PE, TargetArchitecture::Arm | TargetArchitecture::Aarch64, _) => {
            Err("the IDA SDK does not provide a Windows-on-ARM user debugger backend".to_string())
        }
        _ => Err(format!(
            "no debugger probe mapping for target {file_type:?}/{architecture:?}"
        )),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [idb, executable, connection_args @ ..] = args.as_slice() else {
        return Err(USAGE.into());
    };
    let connection = parse_connection(connection_args)?;

    init_library()?;
    let mut options = IDBOpenOptions::new();
    options.save(false).auto_analyse(false);
    let idb_exists = std::path::Path::new(idb).exists();
    if !idb_exists {
        options.idb(idb);
    }
    let database = options.open(if idb_exists { idb } else { executable })?;
    let architecture = target_architecture(&database)?;
    let backend = debugger_backend(
        database.meta().filetype(),
        architecture,
        connection.use_remote,
    )?;
    database.debugger_load(
        backend,
        connection.use_remote,
        connection.host.as_deref(),
        connection.port,
    )?;
    let event_code = database.debugger_launch(executable, None, None, 30)?;
    let modules = database.debugger_modules()?;
    println!(
        "backend={backend} target={:?}/{architecture:?} remote={} event_code={event_code} state={:?}",
        database.meta().filetype(),
        connection.use_remote,
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
    use idalib::meta::FileType;

    use crate::{DebuggerConnection, TargetArchitecture, debugger_backend, parse_connection};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn loaded_x86_64_macho_selects_mac_backend() {
        assert_eq!(
            debugger_backend(FileType::MACHO, TargetArchitecture::X86_64, true),
            Ok("mac")
        );
    }

    #[test]
    fn loaded_aarch64_macho_selects_arm_mac_backend() {
        assert_eq!(
            debugger_backend(FileType::MACHO, TargetArchitecture::Aarch64, true),
            Ok("arm_mac")
        );
    }

    #[test]
    fn arm_linux_requires_remote_transport() {
        let error = debugger_backend(FileType::ELF, TargetArchitecture::Aarch64, false)
            .expect_err("local ARM Linux debugging must be rejected");

        assert!(error.contains("remote-only"), "unexpected error: {error}");
    }

    #[test]
    fn remote_arm_linux_selects_armlinux_backend() {
        assert_eq!(
            debugger_backend(FileType::ELF, TargetArchitecture::Aarch64, true),
            Ok("armlinux")
        );
    }

    #[test]
    fn windows_arm_target_is_rejected() {
        let error = debugger_backend(FileType::PE, TargetArchitecture::Aarch64, true)
            .expect_err("Windows ARM debugging must be rejected");

        assert!(
            error.contains("Windows-on-ARM"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn local_connection_is_explicit() {
        assert_eq!(
            parse_connection(&args(&["local"])),
            Ok(DebuggerConnection {
                use_remote: false,
                host: None,
                port: None,
            })
        );
    }

    #[test]
    fn remote_connection_requires_host_and_port() {
        assert_eq!(
            parse_connection(&args(&["remote", "127.0.0.1", "23946"])),
            Ok(DebuggerConnection {
                use_remote: true,
                host: Some("127.0.0.1".to_string()),
                port: Some(23946),
            })
        );
    }
}
