use std::prelude::v1::*;

use sgx_rand::{os::SgxRng, Rng};
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_tse::{rsgx_create_report, rsgx_verify_report};
use sgx_types::*;
use sgx_types::sgx_status_t::SGX_SUCCESS;

extern "C" {
    /// Ocall to use sgx_init_quote_ex to init the quote and key_id.
    fn ocall_sgx_init_quote(
        p_retval: *mut sgx_status_t,
        p_sgx_att_key_id: *mut sgx_att_key_id_t,
        p_target_info: *mut sgx_target_info_t,
    ) -> sgx_status_t;

    /// Ocall to get the required buffer size for the quote.
    fn ocall_sgx_get_quote_size(
        p_retval: *mut sgx_status_t,
        p_sgx_att_key_id: *const sgx_att_key_id_t,
        p_quote_size: *mut u32,
    ) -> sgx_status_t;

    /// Ocall to use sgx_get_quote_ex to generate a quote with enclave's report.
    fn ocall_sgx_get_quote(
        p_retval: *mut sgx_status_t,
        p_report: *const sgx_report_t,
        p_sgx_att_key_id: *const sgx_att_key_id_t,
        p_qe_report_info: *mut sgx_qe_report_info_t,
        p_quote: *mut u8,
        quote_size: u32,
    ) -> sgx_status_t;

    /// OCall to get target information of myself.
    fn sgx_self_target(p_target_info: *mut sgx_target_info_t) -> sgx_status_t;
}


/// Initialize SGX quote, return attestation key ID selected by the platform and
/// target information for creating report that only QE can verify.
pub fn init_sgx_quote() -> Result<(sgx_att_key_id_t, sgx_target_info_t), sgx_status_t> {
    println!("[+] init_quote");
    let mut ti = sgx_target_info_t::default();
    let mut ak_id = sgx_att_key_id_t::default();
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe { ocall_sgx_init_quote(&mut rt as _, &mut ak_id as _, &mut ti as _) };

    if res != SGX_SUCCESS {
        return Err(res);
    }
    if rt != SGX_SUCCESS {
        return Err(rt);
    }

    Ok((ak_id, ti))
}

/// Create report of the enclave with target_info.
pub fn create_sgx_isv_enclave_report(
    pub_k: sgx_ec256_public_t,
    target_info: sgx_target_info_t,
) -> Result<sgx_report_t, sgx_status_t> {
    println!("[+] create_report");
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx;
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy;
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let report =
        rsgx_create_report(&target_info, &report_data)?;

    Ok(report)
}

/// Get quote with attestation key ID and enclave's local report.
pub fn get_sgx_quote(ak_id: &sgx_att_key_id_t, report: sgx_report_t) -> Result<Vec<u8>, sgx_status_t> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut quote_len: u32 = 0;

    let res = unsafe { ocall_sgx_get_quote_size(&mut rt as _, ak_id as _, &mut quote_len as _) };

    if res != SGX_SUCCESS {
        return Err(res);
    }
    if rt != SGX_SUCCESS {
        return Err(rt);
    }

    let mut qe_report_info = sgx_qe_report_info_t::default();
    let mut quote_nonce = sgx_quote_nonce_t::default();

    let mut rng = SgxRng::new().unwrap();   // SgxRng Error
    rng.fill_bytes(&mut quote_nonce.rand);
    qe_report_info.nonce = quote_nonce;

    println!("[+] sgx_self_target");
    // Provide the target information of ourselves so that we can verify the QE report
    // returned with the quote
    let res = unsafe { sgx_self_target(&mut qe_report_info.app_enclave_target_info as _) };

    if res != SGX_SUCCESS {
        return Err(res);
    }

    let mut quote = vec![0; quote_len as usize];

    println!("[+] ocall_sgx_get_quote");
    let res = unsafe {
        ocall_sgx_get_quote(
            &mut rt as _,
            &report as _,
            ak_id as _,
            &mut qe_report_info as _,
            quote.as_mut_ptr(),
            quote_len,
        )
    };

    if res != SGX_SUCCESS {
        return Err(res);
    }
    if rt != SGX_SUCCESS {
        return Err(rt);
    }

    println!("[+] rsgx_verify_report");
    let qe_report = qe_report_info.qe_report;
    // Perform a check on qe_report to verify if the qe_report is valid.
    rsgx_verify_report(&qe_report)?;

    // Check qe_report to defend against replay attack. The purpose of
    // p_qe_report is for the ISV enclave to confirm the QUOTE it received
    // is not modified by the untrusted SW stack, and not a replay. The
    // implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify
    // the p_qe_report and report.data to confirm the QUOTE has not be
    // modified and is not a replay. It is optional.
    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&quote);
    println!("[+] rsgx_sha256_slice");
    let rhs_hash = rsgx_sha256_slice(&rhs_vec)?;
    let lhs_hash = &qe_report.body.report_data.d[..32];
    if rhs_hash != lhs_hash {
        println!("[-] Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    Ok(quote)
}