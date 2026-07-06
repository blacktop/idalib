use std::ffi::CString;

use crate::ffi::dscu::{
    dscu_image_info, dscu_region_info, dscu_string_match, dscu_symbol_match, idalib_dscu_available,
    idalib_dscu_find_strings, idalib_dscu_find_symbols, idalib_dscu_get_image_dependencies,
    idalib_dscu_get_image_index, idalib_dscu_get_image_info, idalib_dscu_get_images,
    idalib_dscu_get_region_by_ea, idalib_dscu_images_count, idalib_dscu_input_file_path,
    idalib_dscu_load_image, idalib_dscu_load_region,
};
use crate::{Address, IDAError};

pub mod symbol_flags {
    pub const LOADED_IMAGES_ONLY: u32 = 0x1;
    pub const CASE_INSENSITIVE: u32 = 0x2;
}

pub mod string_flags {
    pub const SCOPE_IMAGES: u32 = 0x00;
    pub const SCOPE_FILES: u32 = 0x01;
    pub const IMAGES_SCOPE_DATA_SECTIONS: u32 = 0x00;
    pub const IMAGES_SCOPE_ALL: u32 = 0x02;
    pub const FILES_INCLUDE_SYMBOLS: u32 = 0x04;
    pub const FILES_INCLUDE_BRANCH_MAPPINGS: u32 = 0x08;
    pub const FILES_INCLUDE_OTHER: u32 = 0x10;
    pub const CASE_INSENSITIVE: u32 = 0x20;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub index: i32,
    pub name: String,
    pub file_name: String,
    pub address: Address,
    pub total_size: u64,
    pub file_index: Option<u64>,
    pub loaded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    ImageEntity,
    Island,
    Header,
    Mapping,
    Unknown,
    Got,
    CacheData,
    Invalid(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionInfo {
    pub start: Address,
    pub size: u64,
    pub kind: RegionKind,
    pub image_index: i32,
    pub name: String,
    pub loaded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolMatch {
    pub symbol: String,
    pub address: Address,
    pub image_index: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringMatch {
    pub address: Address,
    pub image_index: i32,
    pub file_index: u64,
    pub file_offset: u64,
    pub context: String,
}

fn unavailable_error() -> IDAError {
    IDAError::ffi_with("IDA dscu service is not available for the current database")
}

fn failed_error(action: impl Into<String>) -> IDAError {
    IDAError::ffi_with(action.into())
}

fn cstring(value: &str) -> Result<CString, IDAError> {
    CString::new(value).map_err(IDAError::ffi)
}

fn image_from_ffi(info: dscu_image_info) -> ImageInfo {
    ImageInfo {
        index: info.index,
        name: info.name,
        file_name: info.file_name,
        address: info.address,
        total_size: info.total_size,
        file_index: u64::try_from(info.file_index).ok(),
        loaded: info.loaded,
    }
}

fn region_kind(raw: i32) -> RegionKind {
    match raw {
        0 => RegionKind::ImageEntity,
        1 => RegionKind::Island,
        2 => RegionKind::Header,
        3 => RegionKind::Mapping,
        4 => RegionKind::Unknown,
        5 => RegionKind::Got,
        6 => RegionKind::CacheData,
        other => RegionKind::Invalid(other),
    }
}

fn region_from_ffi(info: dscu_region_info) -> RegionInfo {
    RegionInfo {
        start: info.start,
        size: info.size,
        kind: region_kind(info.region_type),
        image_index: info.image_index,
        name: info.name,
        loaded: info.loaded,
    }
}

fn symbol_from_ffi(value: dscu_symbol_match) -> SymbolMatch {
    SymbolMatch {
        symbol: value.symbol,
        address: value.address,
        image_index: value.image_index,
    }
}

fn string_from_ffi(value: dscu_string_match) -> StringMatch {
    StringMatch {
        address: value.address,
        image_index: value.image_index,
        file_index: value.file_index,
        file_offset: value.file_offset,
        context: value.context,
    }
}

pub fn is_available() -> bool {
    unsafe { idalib_dscu_available() }
}

pub fn input_file_path() -> Option<String> {
    let path = unsafe { idalib_dscu_input_file_path() };
    if path.is_empty() { None } else { Some(path) }
}

pub fn images_count() -> Option<i32> {
    let count = unsafe { idalib_dscu_images_count() };
    if count < 0 { None } else { Some(count) }
}

pub fn image_index(name: &str) -> Result<Option<i32>, IDAError> {
    let name = cstring(name)?;
    let index = unsafe { idalib_dscu_get_image_index(name.as_ptr()) };
    if index < 0 { Ok(None) } else { Ok(Some(index)) }
}

pub fn image_info(index: i32) -> Option<ImageInfo> {
    let mut out = dscu_image_info::default();
    let ok = unsafe { idalib_dscu_get_image_info(index, &mut out) };
    ok.then(|| image_from_ffi(out))
}

pub fn images() -> Result<Vec<ImageInfo>, IDAError> {
    let mut out = Vec::new();
    if unsafe { idalib_dscu_get_images(&mut out) } {
        Ok(out.into_iter().map(image_from_ffi).collect())
    } else {
        Err(unavailable_error())
    }
}

pub fn image_dependencies(index: i32, depth: i32) -> Result<Vec<ImageInfo>, IDAError> {
    let mut out = Vec::new();
    if unsafe { idalib_dscu_get_image_dependencies(index, depth, &mut out) } {
        Ok(out.into_iter().map(image_from_ffi).collect())
    } else {
        Err(failed_error(format!(
            "failed to get DSC dependencies for image index {index}"
        )))
    }
}

pub fn load_image_index(index: i32) -> Result<ImageInfo, IDAError> {
    let mut out = dscu_image_info::default();
    if unsafe { idalib_dscu_load_image(index, &mut out) } {
        Ok(image_from_ffi(out))
    } else {
        Err(failed_error(format!(
            "failed to load DSC image index {index}"
        )))
    }
}

pub fn load_image(name: &str) -> Result<ImageInfo, IDAError> {
    let Some(index) = image_index(name)? else {
        return Err(failed_error(format!("DSC image not found: {name}")));
    };
    load_image_index(index)
}

pub fn region_by_ea(ea: Address) -> Result<RegionInfo, IDAError> {
    let mut out = dscu_region_info::default();
    if unsafe { idalib_dscu_get_region_by_ea(ea, &mut out) } {
        Ok(region_from_ffi(out))
    } else {
        Err(failed_error(format!(
            "failed to locate DSC region for 0x{ea:x}"
        )))
    }
}

pub fn load_region(ea: Address) -> Result<RegionInfo, IDAError> {
    let mut out = dscu_region_info::default();
    if unsafe { idalib_dscu_load_region(ea, &mut out) } {
        Ok(region_from_ffi(out))
    } else {
        Err(failed_error(format!(
            "failed to load DSC region for 0x{ea:x}"
        )))
    }
}

pub fn find_symbols(
    needle: &str,
    flags: u32,
    max_count: Option<u64>,
) -> Result<Vec<SymbolMatch>, IDAError> {
    let needle = cstring(needle)?;
    let mut out = Vec::new();
    let limit = max_count.unwrap_or(u64::MAX);
    if unsafe { idalib_dscu_find_symbols(needle.as_ptr(), flags, limit, &mut out) } {
        Ok(out.into_iter().map(symbol_from_ffi).collect())
    } else {
        Err(failed_error("failed to query DSC symbols"))
    }
}

pub fn find_strings(
    needle: &str,
    flags: u32,
    max_count: Option<u64>,
) -> Result<Vec<StringMatch>, IDAError> {
    let needle = cstring(needle)?;
    let mut out = Vec::new();
    let limit = max_count.unwrap_or(u64::MAX);
    if unsafe { idalib_dscu_find_strings(needle.as_ptr(), flags, limit, &mut out) } {
        Ok(out.into_iter().map(string_from_ffi).collect())
    } else {
        Err(failed_error("failed to query DSC strings"))
    }
}
