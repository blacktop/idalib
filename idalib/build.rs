fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        if idalib_build::requires_local_ida_install() {
            return Err(
                "IDA installation not found; Linux arm64 builds require a local IDA 9.4 install because the SDK does not ship arm64 Linux stub libraries".into(),
            );
        }
        idalib_build::configure_idasdk_linkage();
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
