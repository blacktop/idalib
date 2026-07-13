#pragma once

#include <cstdint>

#include "pro.h"
#include "ida.hpp"

#include "cxx.h"

inline std::uint16_t idalib_inf_get_version() { return inf_get_version(); }

inline std::uint16_t idalib_inf_get_genflags() { return inf_get_genflags(); }

inline bool idalib_inf_is_auto_enabled() { return inf_is_auto_enabled(); }

inline bool idalib_inf_use_allasm() { return inf_use_allasm(); }

inline bool idalib_inf_loading_idc() { return inf_loading_idc(); }

inline bool idalib_inf_no_store_user_info() { return inf_no_store_user_info(); }

inline bool idalib_inf_readonly_idb() { return inf_readonly_idb(); }

inline bool idalib_inf_check_manual_ops() { return inf_check_manual_ops(); }

inline bool idalib_inf_allow_non_matched_ops() { return inf_allow_non_matched_ops(); }

inline bool idalib_inf_is_graph_view() { return inf_is_graph_view(); }

inline std::uint32_t idalib_inf_get_lflags() { return inf_get_lflags(); }

inline bool idalib_inf_decode_fpp() { return inf_decode_fpp(); }

inline bool idalib_inf_is_32bit_or_higher() { return inf_is_32bit_or_higher(); }
inline bool idalib_inf_is_32bit_exactly()  { return inf_is_32bit_exactly(); }

inline bool idalib_inf_is_16bit() { return inf_is_16bit(); }
inline bool idalib_inf_is_64bit() { return inf_is_64bit(); }

inline bool idalib_inf_is_dll() { return inf_is_dll(); }

inline bool idalib_inf_is_flat_off32() { return inf_is_flat_off32(); }

inline bool idalib_inf_is_be() { return inf_is_be(); }

inline bool idalib_inf_is_wide_high_byte_first() { return inf_is_wide_high_byte_first(); }

inline bool idalib_inf_dbg_no_store_path() { return inf_dbg_no_store_path(); }

inline bool idalib_inf_is_snapshot() { return inf_is_snapshot(); }

inline bool idalib_inf_pack_idb() { return inf_pack_idb(); }

inline bool idalib_inf_compress_idb() { return inf_compress_idb(); }

inline bool idalib_inf_is_kernel_mode() { return inf_is_kernel_mode(); }

inline unsigned int idalib_inf_get_app_bitness() { return inf_get_app_bitness(); }

inline std::uint32_t idalib_inf_get_database_change_count() { return inf_get_database_change_count(); }

inline filetype_t idalib_inf_get_filetype() { return inf_get_filetype(); }

inline std::uint16_t idalib_inf_get_ostype()  { return inf_get_ostype(); }

inline std::uint16_t idalib_inf_get_apptype()  { return inf_get_apptype(); }

inline std::uint8_t idalib_inf_get_asmtype()  { return inf_get_asmtype(); }

inline std::uint8_t idalib_inf_get_specsegs()  { return inf_get_specsegs(); }

inline std::uint32_t idalib_inf_get_af()  { return inf_get_af(); }

inline bool idalib_inf_trace_flow()  { return inf_trace_flow(); }

inline bool idalib_inf_mark_code()  { return inf_mark_code(); }

inline bool idalib_inf_create_jump_tables()  { return inf_create_jump_tables(); }

inline bool idalib_inf_noflow_to_data()  { return inf_noflow_to_data(); }

inline bool idalib_inf_create_all_xrefs()  { return inf_create_all_xrefs(); }

inline bool idalib_inf_create_func_from_ptr()  { return inf_create_func_from_ptr(); }

inline bool idalib_inf_create_func_from_call() { return inf_create_func_from_call(); }

inline bool idalib_inf_create_func_tails() { return inf_create_func_tails(); }

inline bool idalib_inf_should_create_stkvars() { return inf_should_create_stkvars(); }

inline bool idalib_inf_propagate_stkargs() { return inf_propagate_stkargs(); }

inline bool idalib_inf_propagate_regargs() { return inf_propagate_regargs(); }

inline bool idalib_inf_should_trace_sp() { return inf_should_trace_sp(); }

inline bool idalib_inf_full_sp_ana() { return inf_full_sp_ana(); }

inline bool idalib_inf_noret_ana() { return inf_noret_ana(); }

inline bool idalib_inf_guess_func_type() { return inf_guess_func_type(); }

inline bool idalib_inf_truncate_on_del() { return inf_truncate_on_del(); }

inline bool idalib_inf_create_strlit_on_xref() { return inf_create_strlit_on_xref(); }

inline bool idalib_inf_check_unicode_strlits() { return inf_check_unicode_strlits(); }

inline bool idalib_inf_create_off_using_fixup() { return inf_create_off_using_fixup(); }

inline bool idalib_inf_create_off_on_dref() { return inf_create_off_on_dref(); }

inline bool idalib_inf_op_offset() { return inf_op_offset(); }

inline bool idalib_inf_data_offset() { return inf_data_offset(); }

inline bool idalib_inf_use_flirt() { return inf_use_flirt(); }

inline bool idalib_inf_append_sigcmt() { return inf_append_sigcmt(); }

inline bool idalib_inf_allow_sigmulti() { return inf_allow_sigmulti(); }

inline bool idalib_inf_hide_libfuncs() { return inf_hide_libfuncs(); }

inline bool idalib_inf_rename_jumpfunc() { return inf_rename_jumpfunc(); }

inline bool idalib_inf_rename_nullsub() { return inf_rename_nullsub(); }

inline bool idalib_inf_coagulate_data() { return inf_coagulate_data(); }

inline bool idalib_inf_coagulate_code() { return inf_coagulate_code(); }

inline bool idalib_inf_final_pass() { return inf_final_pass(); }

inline std::uint32_t idalib_inf_get_af2()  { return inf_get_af2(); }

inline bool idalib_inf_handle_eh() { return inf_handle_eh(); }

inline bool idalib_inf_handle_rtti() { return inf_handle_rtti(); }

inline bool idalib_inf_macros_enabled() { return inf_macros_enabled(); }

inline bool idalib_inf_merge_strlits() { return inf_merge_strlits(); }

inline uval_t idalib_inf_get_baseaddr()  { return inf_get_baseaddr(); }

inline sel_t idalib_inf_get_start_ss()  { return inf_get_start_ss(); }

inline sel_t idalib_inf_get_start_cs()  { return inf_get_start_cs(); }

inline ea_t idalib_inf_get_start_ip()  { return inf_get_start_ip(); }

inline ea_t idalib_inf_get_start_ea()  { return inf_get_start_ea(); }

inline ea_t idalib_inf_get_start_sp()  { return inf_get_start_sp(); }


inline ea_t idalib_inf_get_main()  { return inf_get_main(); }


inline ea_t idalib_inf_get_min_ea()  { return inf_get_min_ea(); }


inline ea_t idalib_inf_get_max_ea()  { return inf_get_max_ea(); }


inline ea_t idalib_inf_get_omin_ea()  { return inf_get_omin_ea(); }


inline ea_t idalib_inf_get_omax_ea()  { return inf_get_omax_ea(); }


inline ea_t idalib_inf_get_lowoff()  { return inf_get_lowoff(); }


inline ea_t idalib_inf_get_highoff()  { return inf_get_highoff(); }


inline uval_t idalib_inf_get_maxref()  { return inf_get_maxref(); }


inline sval_t idalib_inf_get_netdelta()  { return inf_get_netdelta(); }


inline std::uint8_t idalib_inf_get_xrefnum()  { return inf_get_xrefnum(); }


inline std::uint8_t idalib_inf_get_type_xrefnum()  { return inf_get_type_xrefnum(); }


inline std::uint8_t idalib_inf_get_refcmtnum()  { return inf_get_refcmtnum(); }


inline std::uint8_t idalib_inf_get_xrefflag()  { return inf_get_xrefflag(); }

inline bool idalib_inf_show_xref_seg() { return inf_show_xref_seg(); }

inline bool idalib_inf_show_xref_tmarks() { return inf_show_xref_tmarks(); }

inline bool idalib_inf_show_xref_fncoff() { return inf_show_xref_fncoff(); }

inline bool idalib_inf_show_xref_val() { return inf_show_xref_val(); }


inline std::uint16_t idalib_inf_get_max_autoname_len()  { return inf_get_max_autoname_len(); }


inline char idalib_inf_get_nametype()  { return inf_get_nametype(); }


inline std::uint32_t idalib_inf_get_short_demnames()  { return inf_get_short_demnames(); }


inline std::uint32_t idalib_inf_get_long_demnames()  { return inf_get_long_demnames(); }


inline std::uint8_t idalib_inf_get_demnames()  { return inf_get_demnames(); }


inline std::uint8_t idalib_inf_get_listnames()  { return inf_get_listnames(); }


inline std::uint8_t idalib_inf_get_indent()  { return inf_get_indent(); }


inline std::uint8_t idalib_inf_get_cmt_indent()  { return inf_get_cmt_indent(); }


inline std::uint16_t idalib_inf_get_margin()  { return inf_get_margin(); }


inline std::uint16_t idalib_inf_get_lenxref()  { return inf_get_lenxref(); }


inline std::uint32_t idalib_inf_get_outflags()  { return inf_get_outflags(); }

inline bool idalib_inf_show_void() { return inf_show_void(); }

inline bool idalib_inf_show_auto() { return inf_show_auto(); }

inline bool idalib_inf_gen_null() { return inf_gen_null(); }

inline bool idalib_inf_show_line_pref() { return inf_show_line_pref(); }

inline bool idalib_inf_line_pref_with_seg() { return inf_line_pref_with_seg(); }

inline bool idalib_inf_gen_lzero() { return inf_gen_lzero(); }

inline bool idalib_inf_gen_org() { return inf_gen_org(); }

inline bool idalib_inf_gen_assume() { return inf_gen_assume(); }

inline bool idalib_inf_gen_tryblks() { return inf_gen_tryblks(); }


inline std::uint8_t idalib_inf_get_cmtflg()  { return inf_get_cmtflg(); }

inline bool idalib_inf_show_repeatables() { return inf_show_repeatables(); }

inline bool idalib_inf_show_all_comments() { return inf_show_all_comments(); }
inline bool idalib_inf_set_show_all_comments() { return inf_set_show_all_comments(); }

inline bool idalib_inf_hide_comments() { return inf_hide_comments(); }

inline bool idalib_inf_show_src_linnum() { return inf_show_src_linnum(); }

inline bool idalib_inf_test_mode() { return inf_test_mode(); }
inline bool idalib_inf_show_hidden_insns() { return inf_show_hidden_insns(); }
inline bool idalib_inf_set_show_hidden_insns() { return inf_set_show_hidden_insns(); }

inline bool idalib_inf_show_hidden_funcs() { return inf_show_hidden_funcs(); }
inline bool idalib_inf_set_show_hidden_funcs() { return inf_set_show_hidden_funcs(); }

inline bool idalib_inf_show_hidden_segms() { return inf_show_hidden_segms(); }
inline bool idalib_inf_set_show_hidden_segms() { return inf_set_show_hidden_segms(); }


inline std::uint8_t idalib_inf_get_limiter()  { return inf_get_limiter(); }

inline bool idalib_inf_is_limiter_thin() { return inf_is_limiter_thin(); }

inline bool idalib_inf_is_limiter_thick() { return inf_is_limiter_thick(); }

inline bool idalib_inf_is_limiter_empty() { return inf_is_limiter_empty(); }


inline short idalib_inf_get_bin_prefix_size()  { return inf_get_bin_prefix_size(); }


inline std::uint8_t idalib_inf_get_prefflag()  { return inf_get_prefflag(); }

inline bool idalib_inf_prefix_show_segaddr() { return inf_prefix_show_segaddr(); }

inline bool idalib_inf_prefix_show_funcoff() { return inf_prefix_show_funcoff(); }

inline bool idalib_inf_prefix_show_stack() { return inf_prefix_show_stack(); }

inline bool idalib_inf_prefix_truncate_opcode_bytes() { return inf_prefix_truncate_opcode_bytes(); }


inline std::uint8_t idalib_inf_get_strlit_flags()  { return inf_get_strlit_flags(); }

inline bool idalib_inf_strlit_names() { return inf_strlit_names(); }

inline bool idalib_inf_strlit_name_bit() { return inf_strlit_name_bit(); }

inline bool idalib_inf_strlit_serial_names() { return inf_strlit_serial_names(); }

inline bool idalib_inf_unicode_strlits() { return inf_unicode_strlits(); }

inline bool idalib_inf_strlit_autocmt() { return inf_strlit_autocmt(); }

inline bool idalib_inf_strlit_savecase() { return inf_strlit_savecase(); }


inline std::uint8_t idalib_inf_get_strlit_break()  { return inf_get_strlit_break(); }


inline char idalib_inf_get_strlit_zeroes()  { return inf_get_strlit_zeroes(); }


inline int32 idalib_inf_get_strtype()  { return inf_get_strtype(); }

inline uval_t idalib_inf_get_strlit_sernum()  { return inf_get_strlit_sernum(); }

inline uval_t idalib_inf_get_datatypes()  { return inf_get_datatypes(); }

inline std::uint32_t idalib_inf_get_abibits()  { return inf_get_abibits(); }

inline bool idalib_inf_is_mem_aligned4() { return inf_is_mem_aligned4(); }

inline bool idalib_inf_pack_stkargs() { return inf_pack_stkargs(); }

inline bool idalib_inf_big_arg_align() { return inf_big_arg_align(); }

inline bool idalib_inf_stack_ldbl() { return inf_stack_ldbl(); }

inline bool idalib_inf_stack_varargs() { return inf_stack_varargs(); }

inline bool idalib_inf_is_hard_float() { return inf_is_hard_float(); }

inline bool idalib_inf_abi_set_by_user() { return inf_abi_set_by_user(); }

inline bool idalib_inf_use_gcc_layout() { return inf_use_gcc_layout(); }

inline bool idalib_inf_map_stkargs() { return inf_map_stkargs(); }

inline bool idalib_inf_huge_arg_align() { return inf_huge_arg_align(); }

inline std::uint32_t idalib_inf_get_appcall_options()  { return inf_get_appcall_options(); }

inline ea_t idalib_inf_get_privrange_start_ea()  { return inf_get_privrange_start_ea(); }

inline ea_t idalib_inf_get_privrange_end_ea()  { return inf_get_privrange_end_ea(); }

inline comp_t idalib_inf_get_cc_id()  { return inf_get_cc_id(); }

inline cm_t idalib_inf_get_cc_cm()  { return inf_get_cc_cm(); }

inline std::uint8_t idalib_inf_get_cc_size_i()  { return inf_get_cc_size_i(); }

inline std::uint8_t idalib_inf_get_cc_size_b()  { return inf_get_cc_size_b(); }

inline std::uint8_t idalib_inf_get_cc_size_e()  { return inf_get_cc_size_e(); }

inline std::uint8_t idalib_inf_get_cc_defalign()  { return inf_get_cc_defalign(); }

inline std::uint8_t idalib_inf_get_cc_size_s()  { return inf_get_cc_size_s(); }

inline std::uint8_t idalib_inf_get_cc_size_l()  { return inf_get_cc_size_l(); }

inline std::uint8_t idalib_inf_get_cc_size_ll()  { return inf_get_cc_size_ll(); }

inline std::uint8_t idalib_inf_get_cc_size_ldbl()  { return inf_get_cc_size_ldbl(); }

inline rust::String idalib_inf_get_procname() {
  char buf[IDAINFO_PROCNAME_SIZE];
  if (!getinf_buf(INF_PROCNAME, buf, sizeof(buf))) {
    return rust::String();
  }
  return rust::String(buf);
}

inline rust::String idalib_inf_get_strlit_pref() {
  char buf[IDAINFO_STRLIT_PREF_SIZE];
  if (!getinf_buf(INF_STRLIT_PREF, buf, sizeof(buf))) {
    return rust::String();
  }
  return rust::String(buf);
}

inline bool idalib_inf_get_cc(compiler_info_t *out)  { return inf_get_cc(out); }

inline bool idalib_inf_get_privrange(range_t *out)  { return inf_get_privrange(out); }
