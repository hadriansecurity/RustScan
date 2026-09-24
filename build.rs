#[path = "build/database.rs"]
mod database;
#[path = "build/payload.rs"]
mod payload_parser;

use std::{collections::BTreeMap, env, fmt::Write, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=nmap-payloads");
    println!("cargo:rerun-if-changed=build/database.rs");
    println!("cargo:rerun-if-changed=build/payload.rs");
    let data = fs::read_to_string("nmap-payloads").expect("read nmap-payloads");
    let entries = database::parse(&data).expect("invalid nmap-payloads");

    let mut payloads = Vec::new();
    let mut ports: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    for entry in entries {
        let index = match payloads
            .iter()
            .position(|payload| *payload == entry.payload)
        {
            Some(index) => index,
            None => {
                payloads.push(entry.payload);
                payloads.len() - 1
            }
        };
        for port in entry.ports {
            let variants = ports.entry(port).or_default();
            if !variants.contains(&index) {
                variants.push(index);
            }
        }
    }

    // Merge only adjacent ports with identical variant lists. Overlapping input
    // ranges must retain their combined probes rather than shadowing each other.
    let mut ranges: Vec<(u16, u16, Vec<usize>)> = Vec::new();
    for (port, variants) in ports {
        if let Some((_, end, previous)) = ranges.last_mut() {
            if end.checked_add(1) == Some(port) && *previous == variants {
                *end = port;
                continue;
            }
        }
        ranges.push((port, port, variants));
    }

    let mut code = String::new();
    for (index, payload) in payloads.iter().enumerate() {
        writeln!(code, "static PAYLOAD_{index}: &[u8] = &{payload:?};").unwrap();
    }
    code.push_str("pub fn payloads_for(port: u16) -> &'static [&'static [u8]] {\nmatch port {\n");
    for (start, end, variants) in ranges {
        let variants = variants
            .iter()
            .map(|index| format!("PAYLOAD_{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            code,
            "{start}..={end} => {{ static PROBES: &[&[u8]] = &[{variants}]; PROBES }},"
        )
        .unwrap();
    }
    code.push_str("_ => &[],\n}\n}\n");
    let dest = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("udp_payloads.rs");
    fs::write(dest, code).expect("write generated UDP table");
}
