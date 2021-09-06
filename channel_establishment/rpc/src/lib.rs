#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

mod server;
mod config;
mod endpoint;

pub use config::SgxTrustedTlsServerConfig;
pub use config::SgxTrustedTlsClientConfig;
pub use server::SgxTrustedTlsServer;
pub use endpoint::Endpoint;
