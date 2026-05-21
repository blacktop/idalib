use idalib::{is_valid_license, license_end_date, license_id};

fn main() -> anyhow::Result<()> {
    if !is_valid_license()? {
        println!("invalid license!");
        return Ok(());
    }

    let id = license_id()?;
    println!("license: {id}");

    match license_end_date()? {
        Some(ts) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let days = (ts as i64 - now as i64) / 86_400;
            println!("expires: {ts} (unix), ~{days} days from now");
        }
        None => println!("expires: <unset/perpetual>"),
    }

    Ok(())
}
