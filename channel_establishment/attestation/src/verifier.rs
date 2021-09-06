//! This module provides types used to verify attestation reports.

use crate::report::AttestationReport;
use std::vec::Vec;
use webpki::DNSName;

/// User defined verification function to further verify the attestation report.
pub type AttestationReportVerificationFn = fn(&AttestationReport) -> bool;

/// Type used to verify attestation reports (this can be set as a certificate
/// verifier in `rustls::ClientConfig`).
#[derive(Clone)]
pub struct AttestationReportVerifier {
    /// Root certificate of the attestation service provider (e.g., IAS).
    pub root_ca: Vec<u8>,
    /// User defined function to verify the attestation report.
    pub verifier: AttestationReportVerificationFn,
}

/// Checks if he quote's status is not `UnknownBadStatus`
pub fn universal_quote_verifier(report: &AttestationReport) -> bool {
    println!("[+] report.sgx_quote_status: {:?}", report.sgx_quote_status);
    report.sgx_quote_status != crate::report::SgxQuoteStatus::UnknownBadStatus
}

impl AttestationReportVerifier {
    pub fn new(
        root_ca: &[u8],
        verifier: AttestationReportVerificationFn,
    ) -> Self {
        Self {
            root_ca: root_ca.to_vec(),
            verifier,
        }
    }

    /// Verify TLS certificate.
    fn verify_cert(&self, cert_der: &[u8]) -> bool {
        println!("[+] verify cert");

        let report = match AttestationReport::from_cert(&cert_der, &self.root_ca) {
            Ok(report) => report,
            Err(e) => {
                println!("[-] cert verification error {:?}", e);
                return false;
            }
        };
        (self.verifier)(&report)
    }
}

impl rustls::ServerCertVerifier for AttestationReportVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        // This call automatically verifies certificate signature
        println!("[+] verify server cert");
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }
        if self.verify_cert(&certs[0].0) {
            Ok(rustls::ServerCertVerified::assertion())
        } else {
            Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            ))
        }
    }
}

impl rustls::ClientCertVerifier for AttestationReportVerifier {

    fn client_auth_root_subjects(
        &self,
        _sni: Option<&DNSName>,
    ) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        certs: &[rustls::Certificate],
        _sni: Option<&DNSName>,
    ) -> std::result::Result<rustls::ClientCertVerified, rustls::TLSError> {
        // This call automatically verifies certificate signature
        println!("[+] verify client cert");
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }
        if self.verify_cert(&certs[0].0) {
            Ok(rustls::ClientCertVerified::assertion())
        } else {
            Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            ))
        }
    }
}
