use std::str;
use std::io::{Write, Read};
use crate::config::SgxTrustedTlsServerConfig;

pub struct SgxTrustedTlsServer {
    addr: std::net::SocketAddr,
    tls_config: SgxTrustedTlsServerConfig
}

impl SgxTrustedTlsServer {
    pub fn new(
        addr: std::net::SocketAddr,
        server_config: SgxTrustedTlsServerConfig,
    ) -> SgxTrustedTlsServer {
        Self {
            addr,
            tls_config: server_config,
        }
    }

    pub fn start(self) -> anyhow::Result<()> {
        let listener = std::net::TcpListener::bind(self.addr).expect("bind");
        let tls_config_ref = self.tls_config.server_config();
        println!("[+] server is running");
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let session = rustls::ServerSession::new(&tls_config_ref);
                    let mut tls_stream = rustls::StreamOwned::new(session, stream);
                    let mut plaintext = [0u8;1024];
                    match tls_stream.read(&mut plaintext) {
                        Ok(_) => println!("[+] Client said: {}", str::from_utf8(&plaintext).expect("expect message")),
                        Err(e) => {
                            println!("[-] Error in read_to_end: {:?}", e);
                            panic!("");
                        }
                    };

                    tls_stream.write("hello back".as_bytes()).unwrap();
                }
                Err(e) => {
                    println!("[-] Incoming error: {:}", e);
                }
            }
        }

        Ok(())
    }
}