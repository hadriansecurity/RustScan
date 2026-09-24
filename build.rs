#[path = "build/database.rs"]
mod database;
#[path = "build/payload.rs"]
mod payload_parser;

use std::{env, fmt::Write, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=nmap-payloads");
    println!("cargo:rerun-if-changed=build/database.rs");
    println!("cargo:rerun-if-changed=build/payload.rs");
    let data = fs::read_to_string("nmap-payloads").expect("read nmap-payloads");
    let entries = database::parse(&data).expect("invalid nmap-payloads");

    // Payload bytes are static and shared, even for the broad RPC port range.
    // Only UDP scans initialize the per-port index; no scan clones the table.
    let mut code = String::from(
        "use std::collections::BTreeMap;\n\
         use once_cell::sync::Lazy;\n\
         pub type PayloadMap = BTreeMap<u16, Vec<&'static [u8]>>;\n\
         fn generated_data() -> PayloadMap {\n\
         let mut map = PayloadMap::new();\n",
    );
    for entry in entries {
        writeln!(code, "let payload: &'static [u8] = &{:?};", entry.payload).unwrap();
        writeln!(code, "for port in {:?} {{", entry.ports).unwrap();
        code.push_str(
            "let variants = map.entry(port).or_default();\n\
             if !variants.contains(&payload) { variants.push(payload); }\n}\n",
        );
    }
    code.push_str(
        "map\n}\n\
         static PARSED_DATA: Lazy<PayloadMap> = Lazy::new(generated_data);\n\
         pub fn get_parsed_data() -> &'static PayloadMap { &PARSED_DATA }\n",
    );
    let dest = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("udp_payloads.rs");
    fs::write(dest, code).expect("write generated UDP table");
}
