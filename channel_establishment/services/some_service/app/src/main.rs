use sgx_types::*;
use sgx_urts::SgxEnclave;

mod ocall;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    fn run_client(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

enum Mode {
    Client,
    Server,
}

fn main() {
    let mut mode:Mode = Mode::Server;
    let mut args: Vec<_> = std::env::args().collect();
    args.remove(0);
    while !args.is_empty() {
        match args.remove(0).as_ref() {
            "--client" => mode = Mode::Client,
            "--server" => mode = Mode::Server,
            _ => {
                panic!("Only --client/server are accepted");
            }
        }
    }

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    match mode {
        Mode::Server => {
            println!("[+] Running as server...");
            let mut retval = sgx_status_t::SGX_SUCCESS;
            let ret = unsafe {
                run_server(enclave.geteid(), &mut retval)
            };
            match ret {
                sgx_status_t::SGX_SUCCESS => {
                    println!("[+] ECALL success!");
                },
                _ => {
                    println!("[-] ECALL Enclave Failed {}!", ret.as_str());
                    return;
                }
            }
        }

        Mode::Client => {
            println!("[+] Running as client...");
            let mut retval = sgx_status_t::SGX_SUCCESS;
            let ret = unsafe {
                run_client(enclave.geteid(), &mut retval)
            };
            match ret {
                sgx_status_t::SGX_SUCCESS => {
                    println!("[+] ECALL success!");
                },
                _ => {
                    println!("[-] ECALL Enclave Failed {}!", ret.as_str());
                    return;
                }
            }
        }
    }

    println!("[+] Done!");

    enclave.destroy();
}


