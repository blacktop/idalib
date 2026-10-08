use std::ffi::CString;
use std::fmt;
use std::marker::PhantomData;

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};
use crate::ffi::hexrays::{
    addr_range, cblock_iter, cblock_t, cfunc_t, cfuncptr_t, cinsn_t, decompiler_lvar_info,
    eamap_result, idalib_hexrays_cblock_iter, idalib_hexrays_cblock_iter_next,
    idalib_hexrays_cblock_len, idalib_hexrays_cfunc_body, idalib_hexrays_cfunc_find_stmts_at,
    idalib_hexrays_cfunc_get_stmt_bounds, idalib_hexrays_cfunc_has_eamap,
    idalib_hexrays_cfunc_pseudocode, idalib_hexrays_cfuncptr_inner, idalib_hexrays_cinsn_ea,
    idalib_hexrays_cinsn_op, idalib_hexrays_cinsn_print, idalib_hexrays_comment_locations,
    idalib_hexrays_eamap_result_len, idalib_hexrays_eamap_result_next, idalib_hexrays_lvar_count,
    idalib_hexrays_lvar_info, idalib_hexrays_rename_lvar, idalib_hexrays_set_lvar_type,
    idalib_hexrays_set_pseudocode_comment,
};
use crate::idb::IDB;
use crate::{Address, IDAError};

/// Address range covered by a decompiled statement
#[derive(Debug, Clone, Copy)]
pub struct AddressRange {
    pub start: Address,
    pub end: Address,
}

impl From<addr_range> for AddressRange {
    fn from(r: addr_range) -> Self {
        Self {
            start: r.start,
            end: r.end,
        }
    }
}

/// A snapshot of one Hex-Rays local variable or argument.
#[derive(Debug, Clone)]
pub struct LocalVariable {
    pub name: String,
    pub type_name: String,
    pub location: String,
    /// Opaque identity for this SDK version, function, definition address
    /// and location. Independent of the display name and type. `None` when
    /// the SDK cannot serialize the location losslessly. Reanalysis can
    /// retire it.
    pub locator: Option<String>,
    /// IDA's definition address, or `None` if unknown.
    pub definition_address: Option<Address>,
    pub width: i32,
    pub is_argument: bool,
    pub has_user_name: bool,
    pub has_user_type: bool,
}

/// A commentable line in the current Hex-Rays pseudocode: the first rendered
/// line for each end-of-line comment location.
#[derive(Debug, Clone)]
pub struct PseudocodeCommentLocation {
    /// Opaque SDK, function, address, and placement identity. Reanalysis may
    /// retire it. Obtain a new list when an edit rejects a stale locator.
    pub locator: String,
    pub address: Address,
    /// One-based line number in the full pseudocode, for display only.
    pub line_number: u32,
    pub text: String,
    pub comment: String,
}

pub struct CFunction<'a> {
    ptr: *mut cfunc_t,
    _obj: cxx::UniquePtr<cfuncptr_t>,
    _marker: PhantomData<&'a IDB>,
}

pub struct CBlock<'a> {
    ptr: *mut cblock_t,
    func_ptr: *mut cfunc_t,
    _marker: PhantomData<&'a ()>,
}

pub struct CBlockIter<'a> {
    it: cxx::UniquePtr<cblock_iter>,
    func_ptr: *mut cfunc_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CBlockIter<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_cblock_iter_next(self.it.pin_mut()) };

        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                func_ptr: self.func_ptr,
                _marker: PhantomData,
            })
        }
    }
}

pub struct CInsn<'a> {
    ptr: *mut cinsn_t,
    func_ptr: *mut cfunc_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CInsn<'a> {
    /// Get the address associated with this statement.
    pub fn address(&self) -> Address {
        unsafe { idalib_hexrays_cinsn_ea(self.ptr) }
    }

    /// Get the opcode/type of this statement (cit_* constant).
    pub fn opcode(&self) -> i32 {
        unsafe { idalib_hexrays_cinsn_op(self.ptr).0 }
    }

    /// Get the address range covered by this statement.
    pub fn bounds(&self) -> Option<AddressRange> {
        let mut out = addr_range { start: 0, end: 0 };
        let ok = unsafe { idalib_hexrays_cfunc_get_stmt_bounds(self.func_ptr, self.ptr, &mut out) };
        if ok { Some(out.into()) } else { None }
    }
}

impl fmt::Display for CInsn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = unsafe { idalib_hexrays_cinsn_print(self.ptr, self.func_ptr) };
        write!(f, "{}", text)
    }
}

/// Iterator over statements at an address
pub struct StatementsAtAddr<'a> {
    result: cxx::UniquePtr<eamap_result>,
    func: &'a CFunction<'a>,
}

impl<'a> Iterator for StatementsAtAddr<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_eamap_result_next(self.result.pin_mut()) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                func_ptr: self.func.ptr,
                _marker: PhantomData,
            })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { idalib_hexrays_eamap_result_len(self.result.as_ref().unwrap()) };
        (0, Some(len))
    }
}

impl<'a> CFunction<'a> {
    pub(crate) fn new(obj: cxx::UniquePtr<cfuncptr_t>) -> Option<Self> {
        let ptr = unsafe { idalib_hexrays_cfuncptr_inner(obj.as_ref().expect("valid pointer")) };

        if ptr.is_null() {
            return None;
        }

        Some(Self {
            ptr,
            _obj: obj,
            _marker: PhantomData,
        })
    }

    /// Number of local variables in this decompilation.
    pub fn local_variable_count(&self) -> Result<usize, IDAError> {
        // SAFETY: `ptr` is non-null and retained by `_obj` for this IDB-bound
        // CFunction. IDA calls remain on the thread owning the database.
        unsafe { idalib_hexrays_lvar_count(self.ptr) }.map_err(IDAError::ffi)
    }

    /// Get a variable by its index in this decompilation. Indices are not
    /// stable across decompilations or database edits.
    pub fn local_variable(&self, index: usize) -> Result<Option<LocalVariable>, IDAError> {
        let mut out = decompiler_lvar_info::default();
        // SAFETY: `ptr` is retained by `_obj`; the shim bounds-checks `index`
        // and writes only to the exclusively borrowed output value.
        if !unsafe { idalib_hexrays_lvar_info(self.ptr, index, &mut out) }.map_err(IDAError::ffi)? {
            return Ok(None);
        }
        Ok(Some(LocalVariable {
            name: out.name,
            type_name: out.type_name,
            location: out.location,
            locator: (!out.locator.is_empty()).then_some(out.locator),
            definition_address: (out.definition_address != u64::MAX)
                .then_some(out.definition_address),
            width: out.width,
            is_argument: out.is_argument,
            has_user_name: out.has_user_name,
            has_user_type: out.has_user_type,
        }))
    }

    /// Persist a name for one variable from this decompilation. Consumes the
    /// view because the operation invalidates the cached decompilation.
    pub fn rename_local_variable(self, index: usize, name: &str) -> Result<(), IDAError> {
        let name = CString::new(name).map_err(IDAError::ffi)?;
        // SAFETY: `_obj` retains `ptr` through the call; `name` is a live C
        // string. The shim checks the index and catches C++ exceptions at
        // the cxx Result boundary. No reference to the invalidated view escapes.
        unsafe { idalib_hexrays_rename_lvar(self.ptr, index, name.as_ptr()) }.map_err(IDAError::ffi)
    }

    /// Parse and persist a type for one variable. Returns IDA's normalized
    /// type declaration and invalidates this decompilation view.
    pub fn set_local_variable_type(self, index: usize, decl: &str) -> Result<String, IDAError> {
        let decl = CString::new(decl).map_err(IDAError::ffi)?;
        // SAFETY: `_obj` retains `ptr`; `decl` remains a valid C string. The
        // shim checks the index/type and cxx translates C++ exceptions.
        unsafe { idalib_hexrays_set_lvar_type(self.ptr, index, decl.as_ptr()) }
            .map_err(IDAError::ffi)
    }

    /// Get the full pseudocode for this function as a string.
    pub fn pseudocode(&self) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode(self.ptr) }
    }

    /// Discover end-of-line comment locations in the current rendering. Lines
    /// that share a location yield only the first, where Hex-Rays renders it.
    pub fn pseudocode_comment_locations(&self) -> Result<Vec<PseudocodeCommentLocation>, IDAError> {
        // SAFETY: `_obj` retains the non-null cfunc on the IDB-owning thread.
        // The bounded shim returns owned strings and translates C++ exceptions.
        let locations =
            unsafe { idalib_hexrays_comment_locations(self.ptr) }.map_err(IDAError::ffi)?;
        Ok(locations
            .into_iter()
            .map(|location| PseudocodeCommentLocation {
                locator: location.locator,
                address: location.address,
                line_number: location.line_number,
                text: location.text,
                comment: location.comment,
            })
            .collect())
    }

    /// Set or remove (with empty text) a comment at a current location.
    /// Consumes the view because the edit invalidates cached decompilation.
    pub fn set_pseudocode_comment(self, locator: &str, comment: &str) -> Result<(), IDAError> {
        let locator = CString::new(locator).map_err(IDAError::ffi)?;
        let comment = CString::new(comment).map_err(IDAError::ffi)?;
        // SAFETY: `_obj` retains `ptr`; both C strings live through the call.
        // The shim validates and matches a current native location, catches
        // C++ exceptions, and no reference to the invalidated view escapes.
        unsafe {
            idalib_hexrays_set_pseudocode_comment(self.ptr, locator.as_ptr(), comment.as_ptr())
        }
        .map_err(IDAError::ffi)
    }

    /// Get the function body as a CBlock.
    pub fn body(&self) -> CBlock<'_> {
        let ptr = unsafe { idalib_hexrays_cfunc_body(self.ptr) };

        CBlock {
            ptr,
            func_ptr: self.ptr,
            _marker: PhantomData,
        }
    }

    /// Check if the address-to-statement mapping is available.
    /// This should be true after decompilation.
    pub fn has_eamap(&self) -> bool {
        unsafe { idalib_hexrays_cfunc_has_eamap(self.ptr) }
    }

    /// Find decompiled statements that correspond to a specific address.
    ///
    /// This is useful for finding what pseudocode corresponds to a basic block
    /// or specific instruction address.
    ///
    /// Returns `None` if no statements are found at the address.
    pub fn statements_at(&self, addr: Address) -> Option<StatementsAtAddr<'_>> {
        let result = unsafe { idalib_hexrays_cfunc_find_stmts_at(self.ptr, addr) };
        if result.is_null() {
            None
        } else {
            Some(StatementsAtAddr { result, func: self })
        }
    }

    /// Get pseudocode for statements in an address range (like a basic block).
    ///
    /// This collects all unique statements that cover any part of the given range
    /// and renders them as text.
    pub fn pseudocode_for_range(&self, start: Address, end: Address) -> Vec<String> {
        let mut seen_eas = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Iterate through addresses in the range
        let mut addr = start;
        while addr < end {
            if let Some(stmts) = self.statements_at(addr) {
                for stmt in stmts {
                    let stmt_ea = stmt.address();
                    if seen_eas.insert(stmt_ea) {
                        results.push(stmt.to_string());
                    }
                }
            }
            addr += 1; // Move to next address
        }

        results
    }
}

impl<'a> CBlock<'a> {
    pub fn iter(&self) -> CBlockIter<'_> {
        CBlockIter {
            it: unsafe { idalib_hexrays_cblock_iter(self.ptr) },
            func_ptr: self.func_ptr,
            _marker: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_cblock_len(self.ptr) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
