
use sgx_types::*;
use std::ptr;

#[link(name = "sgx_quote_ex")]
extern "C" {
    fn sgx_select_att_key_id(
        p_att_key_id_list: *const u8,
        att_key_idlist_size: u32,
        p_att_key_id: *mut sgx_att_key_id_t,
    ) -> sgx_status_t;

    fn sgx_init_quote_ex(
        p_att_key_id: *const sgx_att_key_id_t,
        p_qe_target_info: *mut sgx_target_info_t,
        p_pub_key_id_size: *mut usize,
        p_pub_key_id: *mut u8,
    ) -> sgx_status_t;

    fn sgx_get_quote_size_ex(
        p_att_key_id: *const sgx_att_key_id_t,
        p_quote_size: *mut u32,
    ) -> sgx_status_t;

    fn sgx_get_quote_ex(
        p_isv_enclave_report: *const sgx_report_t,
        p_att_key_id: *const sgx_att_key_id_t,
        p_qe_report: *mut sgx_qe_report_info_t,
        p_quote: *mut u8,
        quote_size: u32,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    p_att_key_id: *mut sgx_att_key_id_t,
    p_qe_target_info: *mut sgx_target_info_t,
) -> sgx_status_t {
    let ret = unsafe { sgx_select_att_key_id(ptr::null(), 0, p_att_key_id) };

    if ret != sgx_status_t::SGX_SUCCESS {
        return ret;
    }

    // First call to sgx_init_quote_ex to get att_pub_key_id_size
    let mut att_pub_key_id_size = 0usize;
    let ret = unsafe {
        sgx_init_quote_ex(
            p_att_key_id,
            p_qe_target_info,
            &mut att_pub_key_id_size as _,
            ptr::null_mut(),
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        return ret;
    }

    // Second call to sgx_init_quote_ex to get att_pub_key_id
    // At this point, it is unknown what att_pub_key_id is used for.
    let mut att_pub_key_id: Vec<u8> = vec![0u8; att_pub_key_id_size];
    unsafe {
        sgx_init_quote_ex(
            p_att_key_id,
            p_qe_target_info,
            &mut att_pub_key_id_size as _,
            att_pub_key_id.as_mut_ptr(),
        )
    }
}

#[no_mangle]
pub extern "C" fn ocall_sgx_get_quote_size(
    p_att_key_id: *const sgx_att_key_id_t,
    p_quote_size: *mut u32,
) -> sgx_status_t {
    unsafe { sgx_get_quote_size_ex(p_att_key_id as _, p_quote_size) }
}

#[no_mangle]
pub extern "C" fn ocall_sgx_get_quote(
    p_report: *const sgx_report_t,
    p_att_key_id: *const sgx_att_key_id_t,
    p_qe_report_info: *mut sgx_qe_report_info_t,
    p_quote: *mut u8,
    quote_size: u32,
) -> sgx_status_t {
    unsafe {
        sgx_get_quote_ex(
            p_report,
            p_att_key_id,
            p_qe_report_info,
            p_quote as _,
            quote_size,
        )
    }
}
