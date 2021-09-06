use crate::platform;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::sync::Arc;

use serde_json::json;

use crate::EndorsedAttestationReport;
use crate::DcapConfig;

/// Root certification of the DCAP attestation service provider.
const DCAP_ROOT_CA_CERT: &str = include_str!("../../../keys/dcap_root_ca_cert.pem");

/// URL path to get the report from the DCAP attestation service.
const AS_REPORT_URL: &str = "/sgx/dev/attestation/v4/report";

impl EndorsedAttestationReport {
    pub fn new(
        dcap_cfg: &DcapConfig,
        pub_k: sgx_types::sgx_ec256_public_t,
    ) -> anyhow::Result<Self> {
        let (mut ak_id, qe_target_info) = platform::init_sgx_quote().expect("init_sgx_quote");

        let sgx_report = platform::create_sgx_isv_enclave_report(pub_k, qe_target_info).expect("create_sgx_isv_enclave_report");
        let quote = platform::get_sgx_quote(&ak_id, sgx_report).expect("get_sgx_quote");
        let as_report = get_report(
            &dcap_cfg.as_url,
            &quote,
        )?;

        Ok(as_report)
    }
}


fn new_tls_stream(url: &url::Url) -> anyhow::Result<rustls::StreamOwned<rustls::ClientSession, TcpStream>> {
    let host_str = url
        .host_str()
        .expect("valid address");
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(host_str).expect("dns name");
    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_pem_file(&mut DCAP_ROOT_CA_CERT.to_string().as_bytes())
        .unwrap();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let client = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let addrs = url.socket_addrs(|| match url.scheme() {
        "https" => Some(443),
        _ => None,
    }).expect("address");
    let socket = TcpStream::connect(&*addrs).expect("connect");
    let stream = rustls::StreamOwned::new(client, socket);

    Ok(stream)
}

/// Get attestation report form customized DCAP attestation service.
fn get_report(
    url: &url::Url,
    quote: &[u8],
) -> anyhow::Result<EndorsedAttestationReport> {
    println!("[+] get_report");
    let encoded_quote = base64::encode(quote);
    let encoded_json = json!({ "isvEnclaveQuote": encoded_quote }).to_string();
    let host_str = url
        .host_str()
        .expect("valid address");

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         HOST: {}\r\n\
         Ocp-Apim-Subscription-Key: 00000000000000000000000000000000\r\n\
         Connection: Close\r\n\
         Content-Length: {}\r\n\
         Content-Type: application/json\r\n\r\n\
         {}",
        AS_REPORT_URL,
        host_str,
        encoded_json.len(),
        encoded_json
    );
    println!("[+] TRACE:{}", request);

    let mut stream = new_tls_stream(url)?;
    stream.write_all(request.as_bytes()).expect("stream write");

    // Workaround of https://github.com/ctz/rustls/issues/380
    // Waiting for publish of https://github.com/ctz/rustls/pull/629
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let ret = stream.read(&mut buf);
        match ret {
            Ok(0) => break,
            Ok(n) => response.extend(&buf[..n]),
            Err(e) if e.to_string().contains("CloseNotify alert received") => break,
            _ => {
                println!("[-] rustls read error");
                panic!("");
            }
        }
    }


    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut http_response = httparse::Response::new(&mut headers);

    println!("[+] http_response.parse");
    let header_len = match http_response
        .parse(&response)
        .unwrap()
    {
        httparse::Status::Complete(s) => s,
        _ => panic!("[-] InvalidResponse"),
    };

    let msg : &'static str = 
        match http_response.code {
            Some(200) => "[+] OK Operation Successful",
            Some(401) => "[-] Unauthorized Failed to authenticate or authorize request.",
            Some(500) => "[-] Internal error occurred",
            Some(503) => "[-] Service is currently not able to process the request (due to
                        a temporary overloading or maintenance). This is a
                        temporary state – the same request can be repeated after
                        some time. ",
            _ => {
                println!("DBG:{}", http_response.code.unwrap());
                "[-] Unknown error occured"
            },
        };
    println!("{}", msg);

    let header_map = parse_headers(&http_response);

    println!("[+] get_content_length");
    if !header_map.contains_key("content-length")
        || header_map
            .get("content-length")
            .expect("content-length")
            .parse::<u32>()
            .unwrap_or(0)
            == 0
    {
        panic!("[-] MissingHeader: content-length");
    }

    println!("[+] get_signature");
    let signature = header_map
        .get("x-dcapreport-signature")
        .expect("signature_header");
    let signature = base64::decode(signature).expect("decode");

    println!("[+] get_signing_cert");
    let signing_cert = {
        let cert_str = header_map.get("x-dcapreport-signing-certificate").expect("signing_cert");
        let decoded_cert = percent_encoding::percent_decode_str(cert_str).decode_utf8().expect("decode");
        let certs = rustls::internal::pemfile::certs(&mut decoded_cert.as_bytes()).expect("pemfile");
        certs[0].0.clone()
    };

    println!("[+] return_report");
    let report = response[header_len..].to_vec();
    Ok(EndorsedAttestationReport {
        report,
        signature,
        signing_cert,
    })
}

fn parse_headers(resp: &httparse::Response) -> HashMap<String, String> {
    println!("[+] parse_headers");
    let mut header_map = HashMap::new();
    for h in resp.headers.iter() {
        header_map.insert(
            h.name.to_lowercase(),
            String::from_utf8_lossy(h.value).into_owned(),
        );
    }

    header_map
}