// Run as an example in the pinned reference checkout; see udp_payloads_expected.txt.
use rustscan::generated::get_parsed_data;
use rustscan::scanner::build_udp_payload_lookup;

fn main() {
    let lookup = build_udp_payload_lookup(get_parsed_data());
    let mut start = 0u32;
    while start <= u32::from(u16::MAX) {
        let probes = lookup.get(&(start as u16)).unwrap_or(&[]);
        let mut end = start;
        while end < u32::from(u16::MAX) && lookup.get(&((end + 1) as u16)).unwrap_or(&[]) == probes
        {
            end += 1;
        }
        if !probes.is_empty() {
            print!("{start}-{end}");
            for probe in probes {
                print!(" ");
                for byte in *probe {
                    print!("{byte:02x}");
                }
            }
            println!();
        }
        start = end + 1;
    }
}
