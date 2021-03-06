//! This crate provides TLS-based remote attestation mechanism for Rpc services,
//! supporting ECDSA attestation. DCAP used for RA.

// TODO error handling 

#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

use std::prelude::v1::*;

use serde::{Deserialize, Serialize};

pub struct DcapConfig {
    /// URL of attestation service
    as_url: url::Url,
}

impl DcapConfig {
    pub fn new(url: url::Url) -> Self {
        Self {
            as_url: url
        }
    }
}

/// AttestationReport can be endorsed by either the Intel Attestation Service
/// using EPID or Data Center Attestation
/// Service (platform dependent) using ECDSA.
#[derive(Default, Serialize, Deserialize)]
pub struct EndorsedAttestationReport {
    /// Attestation report generated by the hardware
    pub report: Vec<u8>,
    /// Singature of the report
    pub signature: Vec<u8>,
    /// Certificate matching the signing key of the signature
    pub signing_cert: Vec<u8>,
}

/// Configuration for TLS communication in Remote Attestation
#[derive(Debug)]
pub struct AttestedTlsConfig {
    pub cert: Vec<u8>,
    pub private_key: Vec<u8>,
    pub time: std::time::SystemTime,
    pub validity: std::time::Duration,
}

#[macro_use]
mod cert;
mod attestation;
mod key;
mod platform;
mod service;
pub mod verifier;
pub mod report;

pub use attestation::RemoteAttestation;


/// Errors that can happen during attestation and verification process
#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    #[error("OCall error")]
    OCallError(sgx_types::sgx_status_t),
    #[error("Attestation Service error")]
    AttestationServiceError,
    #[error("Platform error")]
    PlatformError(sgx_types::sgx_status_t),
    #[error("Report error")]
    ReportError,
    #[error("Report error")]
    ConnectionError,
    #[error("Attestation Service API version not compatible")]
    ApiVersionNotCompatible,
}
