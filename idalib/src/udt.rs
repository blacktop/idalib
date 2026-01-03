use crate::ffi::udt::{
    idalib_get_ordinal_limit, idalib_get_udt_info, idalib_get_udt_member,
    idalib_get_udt_member_tid, udt_info, udt_member_info,
};
use autocxx::c_uint;

#[derive(Debug, Clone)]
pub struct UdtInfo {
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub is_union: bool,
    pub member_count: u32,
}

#[derive(Debug, Clone)]
pub struct UdtMember {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub is_bitfield: bool,
}

pub fn ordinal_limit() -> u32 {
    unsafe { idalib_get_ordinal_limit().into() }
}

pub fn get_udt_info(ordinal: u32) -> Option<UdtInfo> {
    let mut out = udt_info::default();
    let ok = unsafe { idalib_get_udt_info(c_uint(ordinal), &mut out) };
    if !ok {
        return None;
    }
    Some(UdtInfo {
        ordinal,
        name: out.name,
        size: out.size,
        is_union: out.is_union,
        member_count: out.member_count,
    })
}

pub fn get_udt_member(ordinal: u32, index: u32) -> Option<UdtMember> {
    let mut out = udt_member_info::default();
    let ok = unsafe { idalib_get_udt_member(c_uint(ordinal), c_uint(index), &mut out) };
    if !ok {
        return None;
    }
    Some(UdtMember {
        name: out.name,
        type_name: out.type_name,
        offset_bits: out.offset_bits,
        size_bits: out.size_bits,
        is_bitfield: out.is_bitfield,
    })
}

pub fn get_udt_member_tid(ordinal: u32, index: u32) -> Option<u64> {
    let mut tid = 0u64;
    let ok = unsafe { idalib_get_udt_member_tid(c_uint(ordinal), c_uint(index), &mut tid) };
    if !ok {
        return None;
    }
    Some(tid)
}
