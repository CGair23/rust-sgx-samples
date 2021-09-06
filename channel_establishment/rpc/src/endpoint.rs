
use crate::config::SgxTrustedTlsClientConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::prelude::v1::*;
use http::Uri;
use std::sync::Arc;
use std::io::{Write, Read};
use std::str;

pub struct Endpoint {
    url: String,
    config: SgxTrustedTlsClientConfig,
}

impl Endpoint {
    pub fn new(url: &str) -> Self {
        let config = SgxTrustedTlsClientConfig::new();
        Self {
            url: url.to_string(),
            config,
        }
    }

    pub fn connect(&self) -> Result<()>
    {
        let uri = &self.url.parse::<Uri>()?;
        let hostname = uri.host().expect("valid hostname.");
        let stream = std::net::TcpStream::connect(&self.url)?;
        let hostname = webpki::DNSNameRef::try_from_ascii_str(hostname)?;
        let session =
            rustls::ClientSession::new(&Arc::new(self.config.client_config.clone()), hostname);
        let mut tls_stream = rustls::StreamOwned::new(session, stream);
        tls_stream.write("hello".as_bytes()).unwrap();
    
        let mut plaintext = Vec::new();
        match tls_stream.read_to_end(&mut plaintext) {
            Ok(_) => {
                println!("[+] Server replied: {}", str::from_utf8(&plaintext).unwrap());
            }
            Err(ref err) if err.kind() == std::io::ErrorKind::ConnectionAborted => {
                println!("[-] EOF (tls)");
            }
            Err(e) => println!("[-] Error in read_to_end: {:?}", e),
        }

        Ok(())
    }

    pub fn config(self, config: SgxTrustedTlsClientConfig) -> Self {
        Self {
            url: self.url,
            config,
        }
    }
}
