use crate::ffi::types::{
    idalib_apply_decl_type, idalib_apply_named_type, idalib_declare_type, idalib_declare_types,
    idalib_get_local_type, idalib_guess_tinfo, local_type_info, type_decl_result,
    type_guess_result,
};
use autocxx::c_uint;
use std::ffi::CString;

#[derive(Debug, Clone)]
pub struct LocalTypeInfo {
    pub ordinal: u32,
    pub name: String,
    pub decl: String,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct DeclaredType {
    pub code: i32,
    pub name: String,
    pub decl: String,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct GuessType {
    pub code: i32,
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

pub fn declare_type(decl: &str, relaxed: bool, replace: bool) -> DeclaredType {
    let c_decl = CString::new(decl).unwrap_or_else(|_| CString::new("").unwrap());
    let mut out = type_decl_result::default();
    let _ = unsafe { idalib_declare_type(c_decl.as_ptr(), relaxed, replace, &mut out) };
    DeclaredType {
        code: out.code,
        name: out.name,
        decl: out.decl,
        kind: out.kind,
    }
}

pub fn declare_types(decls: &str, relaxed: bool) -> i32 {
    let c_decls = CString::new(decls).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe { idalib_declare_types(c_decls.as_ptr(), relaxed).into() }
}

pub fn apply_decl_type(addr: u64, decl: &str, relaxed: bool, delay: bool, strict: bool) -> bool {
    let c_decl = CString::new(decl).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe { idalib_apply_decl_type(addr, c_decl.as_ptr(), relaxed, delay, strict) }
}

pub fn apply_named_type(addr: u64, name: &str) -> bool {
    let c_name = CString::new(name).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe { idalib_apply_named_type(addr, c_name.as_ptr()) }
}

pub fn guess_type(id: u64) -> GuessType {
    let mut out = type_guess_result::default();
    let _ = unsafe { idalib_guess_tinfo(id, &mut out) };
    GuessType {
        code: out.code,
        decl: out.decl,
        kind: out.kind,
    }
}
