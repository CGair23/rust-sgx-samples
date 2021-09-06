use std::env;

fn main () {

    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/sgxsdk".to_string());

    println!("cargo:rustc-link-search=native=../lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
}