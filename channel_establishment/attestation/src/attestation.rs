use std::prelude::v1::*;

use std::sync::{Arc, SgxRwLock as RwLock};

use crate::DcapConfig;
use crate::AttestedTlsConfig;
use crate::EndorsedAttestationReport;
use crate::key;
use std::time::{Duration, SystemTime};
use std::untrusted::time::SystemTimeEx;

const CERT_ISSUER: &str = "Teaclave";
const CERT_SUBJECT: &str = "CN=Teaclave";
const ATTESTATION_VALIDITY_SECS: u64 = 36000;

pub struct RemoteAttestation {
    dcap_config: Arc<DcapConfig>,
    attested_tls_config: Option<Arc<RwLock<AttestedTlsConfig>>>,
}

impl RemoteAttestation {
    /// Construct a `RemoteAttestation` with attestation configuration.
    pub fn new(dcap_config: Arc<DcapConfig>) -> Self {
        Self {
            dcap_config: dcap_config,
            attested_tls_config: None,
        }
    }

    /// Generate a endorsed attestation report.
    pub fn generate_and_endorse(self) -> anyhow::Result<Self> {
        let attested_tls_config = Arc::new(RwLock::new(AttestedTlsConfig::new(
            &self.dcap_config,
        )?));
        // TODO
        // AttestationFreshnessKeeper
        Ok(Self {
            dcap_config: self.dcap_config,
            attested_tls_config: Some(attested_tls_config),
        })
    }

    /// Construct a attested TLS config for TLS connection.
    pub fn attested_tls_config(&self) -> Option<Arc<RwLock<AttestedTlsConfig>>> {
        self.attested_tls_config.clone()
    }
}

impl AttestedTlsConfig {
    fn new(dcap_config: &DcapConfig) -> anyhow::Result<AttestedTlsConfig> {
        let key_pair = key::NistP256KeyPair::new().expect("key pair");
        let report = EndorsedAttestationReport::new(&dcap_config, key_pair.pub_k()).expect("report");

        let extension = serde_json::to_vec(&report).expect("extension");
        let cert = key_pair.create_cert_with_extension(CERT_ISSUER, CERT_SUBJECT, &extension);
        let private_key = key_pair.private_key_into_der();
        let time = SystemTime::now();
        let validity = Duration::from_secs(ATTESTATION_VALIDITY_SECS);

        let attested_tls_config = AttestedTlsConfig {
            cert,
            private_key,
            time,
            validity,
        };

        // println!("TRACE: {:?}", attested_tls_config);

        Ok(attested_tls_config)
    }
}