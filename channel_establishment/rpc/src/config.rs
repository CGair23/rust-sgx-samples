use std::prelude::v1::*;
use std::sync::SgxRwLock as RwLock;

use std::sync::Arc;
use std::time::{SystemTime, Duration};
use std::untrusted::time::SystemTimeEx;

use attestation::AttestedTlsConfig;
use attestation::report::AttestationReport;
use attestation::verifier::AttestationReportVerifier;

#[derive(Clone)]
pub struct SgxTrustedTlsServerConfig {
    server_config: rustls::ServerConfig,
    attested_tls_config: Option<Arc<RwLock<AttestedTlsConfig>>>,
    time: SystemTime,
    validity: Duration,
}


impl Default for SgxTrustedTlsServerConfig {
    fn default() -> Self {
        let client_cert_verifier = rustls::NoClientAuth::new();
        let server_config = rustls::ServerConfig::new(client_cert_verifier);
        let time = SystemTime::now();
        let validity = std::time::Duration::from_secs(u64::max_value());

        Self {
            server_config,
            attested_tls_config: None,
            time,
            validity,
        }
    }
}

impl SgxTrustedTlsServerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn server_cert(mut self, cert: &[u8], key_der: &[u8]) -> anyhow::Result<Self> {
        let cert_chain = vec![rustls::Certificate(cert.to_vec())];
        let key_der = rustls::PrivateKey(key_der.to_vec());
        self.server_config.set_single_cert(cert_chain, key_der).expect("set single cert");

        Ok(Self { ..self })
    }

    pub fn from_attested_tls_config(
        attested_tls_config: Arc<RwLock<AttestedTlsConfig>>,
    ) -> anyhow::Result<Self> {
        let lock = attested_tls_config.clone();
        let tls_config = lock.read().unwrap();
        let mut config = Self::new().server_cert(&tls_config.cert, &tls_config.private_key)?;
        config.attested_tls_config = Some(attested_tls_config);
        config.time = tls_config.time;
        config.validity = tls_config.validity;
        Ok(config)
    }

    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::new(self.server_config.clone())
    }
}

pub struct SgxTrustedTlsClientConfig {
    pub client_config: rustls::ClientConfig,
    pub attested_tls_config: Option<Arc<RwLock<AttestedTlsConfig>>>,
    pub validity: Duration,
}

struct NoServerAuth;

impl NoServerAuth {
    // Allow new_ret_no_self, make it consistent with rustls definition of
    // `NoClientAuth::new()`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<dyn rustls::ServerCertVerifier> {
        Arc::new(NoServerAuth)
    }
}

impl rustls::ServerCertVerifier for NoServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

impl Default for SgxTrustedTlsClientConfig {
    fn default() -> Self {
        let mut client_config = rustls::ClientConfig::new();

        client_config
            .dangerous()
            .set_certificate_verifier(NoServerAuth::new());
        client_config.versions.clear();
        client_config
            .versions
            .push(rustls::ProtocolVersion::TLSv1_2);

        Self {
            client_config,
            attested_tls_config: None,
            validity: std::time::Duration::default(),
        }
    }
}


impl SgxTrustedTlsClientConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attestation_report_verifier(
        mut self,
        root_ca: &[u8],
        verifier: fn(&AttestationReport) -> bool,
    ) -> Self {
        let verifier = Arc::new(AttestationReportVerifier::new(
            root_ca,
            verifier,
        ));
        self.client_config
            .dangerous()
            .set_certificate_verifier(verifier);

        Self { ..self }
    }

    pub fn client_cert(mut self, cert: &[u8], key_der: &[u8]) -> Self {
        let cert_chain = vec![rustls::Certificate(cert.to_vec())];
        let key_der = rustls::PrivateKey(key_der.to_vec());
        self.client_config
            .set_single_client_cert(cert_chain, key_der)
            .unwrap();

        Self { ..self }
    }

    pub fn from_attested_tls_config(
        attested_tls_config: Arc<RwLock<AttestedTlsConfig>>,
    ) -> anyhow::Result<Self> {
        let lock = attested_tls_config.clone();
        let tls_config = lock.read().unwrap();
        let mut config = Self::new().client_cert(&tls_config.cert, &tls_config.private_key);
        config.attested_tls_config = Some(attested_tls_config);
        Ok(config)
    }
}