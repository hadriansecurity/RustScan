#[path = "build/nmap_payloads.rs"]
mod nmap_payloads;

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build/nmap_payloads.rs");
    println!("cargo:rerun-if-changed=nmap-service-probes");
    let services = fs::read_to_string("nmap-service-probes").expect("read nmap-service-probes");
    let entries =
        nmap_payloads::parse_service_probes(&services).expect("invalid nmap-service-probes");
    let dest = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("udp_payloads.rs");
    fs::write(dest, nmap_payloads::generate(entries)).expect("write generated UDP table");
}
