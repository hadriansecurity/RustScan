#[path = "build/nmap_payloads.rs"]
mod nmap_payloads;

use std::{fs, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build/nmap_payloads.rs");
    println!("cargo:rerun-if-changed=nmap-service-probes");
    let services = fs::read_to_string("nmap-service-probes").expect("read nmap-service-probes");
    let entries =
        nmap_payloads::parse_service_probes(&services).expect("invalid nmap-service-probes");
    fs::write("src/generated.rs", nmap_payloads::generate(entries))
        .expect("write generated UDP table");
    Command::new("cargo")
        .arg("fmt")
        .arg("--all")
        .output()
        .expect("Failed to execute cargo fmt");
}
