use crate::ffi::frame::{
    frame_info, frame_member_info, idalib_define_stkvar, idalib_delete_stkvar,
    idalib_get_frame_info, idalib_get_frame_member, idalib_set_stkvar_type, stkvar_result,
};
use autocxx::c_uint;
use std::ffi::CString;

#[derive(Debug, Clone)]
pub struct FrameInfo {
    pub frame_size: u64,
    pub ret_size: i32,
    pub frsize: u64,
    pub frregs: u16,
    pub argsize: u64,
    pub fpd: u64,
    pub args_start: u64,
    pub args_end: u64,
    pub retaddr_start: u64,
    pub retaddr_end: u64,
    pub savregs_start: u64,
    pub savregs_end: u64,
    pub locals_start: u64,
    pub locals_end: u64,
    pub member_count: u32,
}

#[derive(Debug, Clone)]
pub struct FrameMember {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub is_bitfield: bool,
    pub part: String,
}

#[derive(Debug, Clone)]
pub struct StackVarResult {
    pub code: i32,
    pub name: String,
    pub offset: i64,
}

pub fn get_frame_info(ea: u64) -> Option<FrameInfo> {
    let mut out = frame_info::default();
    let ok = unsafe { idalib_get_frame_info(ea, &mut out) };
    if !ok {
        return None;
    }
    Some(FrameInfo {
        frame_size: out.frame_size,
        ret_size: out.ret_size,
        frsize: out.frsize,
        frregs: out.frregs,
        argsize: out.argsize,
        fpd: out.fpd,
        args_start: out.args_start,
        args_end: out.args_end,
        retaddr_start: out.retaddr_start,
        retaddr_end: out.retaddr_end,
        savregs_start: out.savregs_start,
        savregs_end: out.savregs_end,
        locals_start: out.locals_start,
        locals_end: out.locals_end,
        member_count: out.member_count,
    })
}

pub fn get_frame_member(ea: u64, index: u32) -> Option<FrameMember> {
    let mut out = frame_member_info::default();
    let ok = unsafe { idalib_get_frame_member(ea, c_uint(index), &mut out) };
    if !ok {
        return None;
    }
    Some(FrameMember {
        name: out.name,
        type_name: out.type_name,
        offset_bits: out.offset_bits,
        size_bits: out.size_bits,
        is_bitfield: out.is_bitfield,
        part: out.part,
    })
}

pub fn define_stack_var(
    ea: u64,
    name: Option<&str>,
    offset: i64,
    decl: &str,
    relaxed: bool,
) -> StackVarResult {
    let mut out = stkvar_result::default();
    let c_name = name.and_then(|v| CString::new(v).ok());
    let c_decl = CString::new(decl).unwrap_or_else(|_| CString::new("").unwrap());
    let _ = unsafe {
        idalib_define_stkvar(
            ea,
            c_name
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            offset,
            c_decl.as_ptr(),
            relaxed,
            &mut out,
        )
    };
    StackVarResult {
        code: out.code,
        name: out.name,
        offset: out.offset,
    }
}

pub fn delete_stack_var(
    ea: u64,
    name: Option<&str>,
    offset: i64,
    use_offset: bool,
) -> StackVarResult {
    let mut out = stkvar_result::default();
    let c_name = name.and_then(|v| CString::new(v).ok());
    let _ = unsafe {
        idalib_delete_stkvar(
            ea,
            c_name
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            offset,
            use_offset,
            &mut out,
        )
    };
    StackVarResult {
        code: out.code,
        name: out.name,
        offset: out.offset,
    }
}

pub fn set_stack_var_type(
    ea: u64,
    name: Option<&str>,
    offset: i64,
    use_offset: bool,
    decl: &str,
    relaxed: bool,
    strict: bool,
) -> StackVarResult {
    let mut out = stkvar_result::default();
    let c_name = name.and_then(|v| CString::new(v).ok());
    let c_decl = CString::new(decl).unwrap_or_else(|_| CString::new("").unwrap());
    let _ = unsafe {
        idalib_set_stkvar_type(
            ea,
            c_name
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            offset,
            use_offset,
            c_decl.as_ptr(),
            relaxed,
            strict,
            &mut out,
        )
    };
    StackVarResult {
        code: out.code,
        name: out.name,
        offset: out.offset,
    }
}
