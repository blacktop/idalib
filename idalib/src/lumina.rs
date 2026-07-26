use crate::ffi::lumina::{idalib_lumina_pull, lumina_pull_result};
use crate::{Address, IDAError, init_library};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullStatus {
    BadPattern,
    NotFound,
    Error,
    Ok,
    Added,
    Unknown(i32),
}

impl PullStatus {
    fn from_raw(code: i32) -> Self {
        match code {
            -3 => Self::BadPattern,
            -2 => Self::NotFound,
            -1 => Self::Error,
            0 => Self::Ok,
            1 => Self::Added,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResult {
    pub status: PullStatus,
    pub name: String,
    pub size: u32,
    pub frequency: u32,
    pub score: u32,
    pub metadata_keys: Vec<&'static str>,
    pub applied: bool,
    pub backup_created: bool,
    pub error: Option<String>,
}

fn metadata_keys(mask: u32) -> Vec<&'static str> {
    const KEYS: &[(u32, &str)] = &[
        (1, "type"),
        (2, "decompilation_elapsed"),
        (3, "function_comment"),
        (4, "function_repeatable_comment"),
        (5, "comments"),
        (6, "repeatable_comments"),
        (7, "extra_comments"),
        (8, "user_stack_points"),
        (9, "frame"),
        (10, "operand_representations"),
        (11, "extended_operand_representations"),
    ];

    let mut present = Vec::new();
    for &(bit, name) in KEYS {
        if mask & (1 << bit) != 0 {
            present.push(name);
        }
    }
    present
}

pub fn pull(address: Address, apply: bool, force: bool) -> Result<PullResult, IDAError> {
    init_library()?;
    let mut out = lumina_pull_result::default();
    if !unsafe { idalib_lumina_pull(address, apply, force, &mut out) } {
        let message = if out.error.is_empty() {
            "Lumina metadata request failed".to_string()
        } else {
            out.error
        };
        return Err(IDAError::ffi_with(message));
    }

    Ok(PullResult {
        status: PullStatus::from_raw(out.code),
        name: out.name,
        size: out.size,
        frequency: out.frequency,
        score: out.score,
        metadata_keys: metadata_keys(out.metadata_mask),
        applied: out.applied,
        backup_created: out.backup_created,
        error: (!out.error.is_empty()).then_some(out.error),
    })
}

#[cfg(test)]
mod tests {
    use crate::lumina::{PullStatus, metadata_keys};

    #[test]
    fn pull_status_preserves_unknown_codes() {
        assert_eq!(PullStatus::from_raw(-2), PullStatus::NotFound);
        assert_eq!(PullStatus::from_raw(42), PullStatus::Unknown(42));
    }

    #[test]
    fn metadata_mask_maps_known_fields() {
        assert_eq!(metadata_keys((1 << 1) | (1 << 9)), vec!["type", "frame"]);
    }
}
