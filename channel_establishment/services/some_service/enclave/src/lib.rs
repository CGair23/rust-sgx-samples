#![no_std]

#[macro_use]
extern crate sgx_tstd as std;
use std::prelude::v1::*;

use std::backtrace::{self, PrintFormat};
use std::sync::Arc;

use sgx_types::*;

use attestation::{DcapConfig, RemoteAttestation};
use rpc::{SgxTrustedTlsServer, SgxTrustedTlsServerConfig, SgxTrustedTlsClientConfig, Endpoint};

#[no_mangle]
pub extern "C" fn run_server() -> sgx_status_t {
    let dcap_config = DcapConfig::new(url::Url::parse("https://dcap:8080").unwrap());
    let attested_tls_config = RemoteAttestation::new(Arc::new(dcap_config))
        .generate_and_endorse()
        .expect("endorsed attestation report")
        .attested_tls_config()
        .expect("attested TLS config");
    let server_config =
        match SgxTrustedTlsServerConfig::from_attested_tls_config(attested_tls_config.clone()) {
            Ok(cfg) => cfg,
            _ => {
                println!("[-] fail to get server config");
                panic!("");
            }
        };
    let listen_address = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 4443);
    let server = SgxTrustedTlsServer::new(
        listen_address,
        server_config,
    );

    server.start();

    sgx_status_t::SGX_SUCCESS

}

#[no_mangle]
pub extern "C" fn run_client() -> sgx_status_t {
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);
    let dcap_config = DcapConfig::new(url::Url::parse("https://dcap:8080").unwrap());
    let attested_tls_config = RemoteAttestation::new(Arc::new(dcap_config))
        .generate_and_endorse()
        .expect("endorsed attestation report")
        .attested_tls_config()
        .expect("attested TLS config");
    let service_client_config =
        match SgxTrustedTlsClientConfig::from_attested_tls_config(attested_tls_config) {
            Ok(cfg) => cfg,
            _ => {
                println!("[-] fail to get client config");
                panic!("");
            }
        };
    let service_address = "localhost:4443";

    Endpoint::new(service_address).config(service_client_config).connect();

    sgx_status_t::SGX_SUCCESS
}
