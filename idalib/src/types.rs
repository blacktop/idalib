use crate::ffi::types::{idalib_get_local_type, local_type_info};
use autocxx::c_uint;

#[derive(Debug, Clone)]
pub struct LocalTypeInfo {
    pub ordinal: u32,
    pub name: String,
    pub decl: String,
    pub kind: String,
}

pub fn get_local_type(ordinal: u32) -> Option<LocalTypeInfo> {
    let mut out = local_type_info::default();
    let ok = unsafe { idalib_get_local_type(c_uint(ordinal), &mut out) };
    if !ok {
        return None;
    }
    Some(LocalTypeInfo {
        ordinal,
        name: out.name,
        decl: out.decl,
        kind: out.kind,
    })
}
