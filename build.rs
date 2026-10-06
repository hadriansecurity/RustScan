#[path = "build/nmap_payloads.rs"]
mod nmap_payloads;
#[path = "build/supplemental_payloads.rs"]
mod supplemental_payloads;

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build/nmap_payloads.rs");
    println!("cargo:rerun-if-changed=build/supplemental_payloads.rs");
    println!("cargo:rerun-if-changed=probes/zmap");
    println!("cargo:rerun-if-changed=nmap-service-probes");
    let services = fs::read_to_string("nmap-service-probes").expect("read nmap-service-probes");
    let mut entries =
        nmap_payloads::parse_service_probes(&services).expect("invalid nmap-service-probes");
    entries.extend(
        supplemental_payloads::PROBES
            .iter()
            .map(|&(port, payload)| nmap_payloads::Entry {
                ports: vec![port],
                payload: payload.to_vec(),
            }),
    );
    let dest = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("udp_payloads.rs");
    fs::write(dest, nmap_payloads::generate(entries)).expect("write generated UDP table");
}
