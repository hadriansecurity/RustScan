use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs::{self, File};

use std::env;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process::Command;

// Reads in a file with payloads based on port
pub fn main() {
    let mut file_path = env::current_dir().expect("cant find curr dir");
    file_path.push("./nmap-payloads");

    let mut data = String::new();
    let file = File::open(&file_path).expect("File not found.");
    let mut file_buf = BufReader::new(file);
    file_buf
        .read_to_string(&mut data)
        .expect("unable to read file");

    let mut fp_map: BTreeMap<i32, String> = BTreeMap::new();

    let mut count = 0;
    let mut capturing = false;
    let mut curr = String::new();

    for line in data.trim().split('\n') {
        // Strip a trailing carriage return so CRLF checkouts parse
        // identically to LF ones (otherwise `\r` pollutes port tokens and
        // blank lines stop looking blank).
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = strip_comment(line).trim_end();
        if line.trim_start().is_empty() {
            continue;
        }

        if line.starts_with("udp") {
            if !curr.is_empty() {
                fp_map.insert(count, curr);
                curr = String::new();
            }
            capturing = true;
            count += 1;
        }

        if capturing {
            if !curr.is_empty() {
                curr.push(' ');
            }
            curr.push_str(line);
        }
    }
    if !curr.is_empty() {
        fp_map.insert(count, curr);
    }

    let pb_linenr = ports_v(&fp_map);
    let payb_linenr = payloads_v(&fp_map);
    validate_records(&data, &fp_map, &pb_linenr, &payb_linenr);
    let map = port_payload_map(pb_linenr, payb_linenr);

    generate_code(map);
}

/// Removes a trailing `#` comment from a line of the payload file.
///
/// A `#` inside a quoted payload segment is payload data, not a comment.
///
/// # Arguments
///
/// * `line` - One line of the payload file
///
/// # Returns
///
/// The line up to, but not including, its first unquoted `#`
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b'#' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Checks that every UDP declaration has collected ports and a parsed payload.
///
/// Count before deduplication, where identical records may legitimately merge.
///
/// # Arguments
///
/// * `data` - The original payload file
/// * `fp_map` - Collected records keyed by line number
/// * `pb_linenr` - Parsed ports keyed by line number
/// * `payb_linenr` - Parsed payloads keyed by line number
fn validate_records(
    data: &str,
    fp_map: &BTreeMap<i32, String>,
    pb_linenr: &BTreeMap<i32, Vec<u16>>,
    payb_linenr: &BTreeMap<i32, Vec<u8>>,
) {
    let expected_records = data
        .trim()
        .lines()
        .filter(|line| line.starts_with("udp"))
        .count();
    assert_eq!(
        fp_map.len(),
        expected_records,
        "lost UDP records while collecting entries"
    );
    assert_eq!(
        pb_linenr.values().filter(|ports| !ports.is_empty()).count(),
        expected_records,
        "a UDP record has no parsed ports"
    );
    assert_eq!(
        payb_linenr.len(),
        expected_records,
        "a UDP record has no parsed payload"
    );
}

/// Deduplicates payload bytes and indexes the ordered probes for each port.
///
/// Probe order follows sorted port-list keys, then file order within each key.
/// Keep the first occurrence of duplicate payload bytes.
///
/// # Arguments
///
/// * `port_payload_map` - A BTreeMap mapping port lists to their payload variants
///
/// # Returns
///
/// Unique payloads and a BTreeMap mapping ports to ordered payload indices
fn index_payloads(
    port_payload_map: BTreeMap<Vec<u16>, Vec<Vec<u8>>>,
) -> (Vec<Vec<u8>>, BTreeMap<u16, Vec<usize>>) {
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut ports: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    for (port_list, variants) in port_payload_map {
        for payload in variants {
            let index = match payloads.iter().position(|known| known == &payload) {
                Some(index) => index,
                None => {
                    payloads.push(payload);
                    payloads.len() - 1
                }
            };
            for &port in &port_list {
                let probes = ports.entry(port).or_default();
                if !probes.contains(&index) {
                    probes.push(index);
                }
            }
        }
    }

    (payloads, ports)
}

/// Coalesces adjacent ports with identical probes into inclusive ranges.
///
/// # Arguments
///
/// * `ports` - A BTreeMap mapping ports to ordered payload indices
///
/// # Returns
///
/// Inclusive start and end ports with the payload indices shared by each range
fn coalesce_port_ranges(ports: BTreeMap<u16, Vec<usize>>) -> Vec<(u16, u16, Vec<usize>)> {
    let mut ranges: Vec<(u16, u16, Vec<usize>)> = Vec::new();
    for (port, probes) in ports {
        if let Some((_, end, previous)) = ranges.last_mut() {
            if end.checked_add(1) == Some(port) && *previous == probes {
                *end = port;
                continue;
            }
        }
        ranges.push((port, port, probes));
    }

    ranges
}

/// Writes the static UDP payload lookup to src/generated.rs and calls cargo fmt.
///
/// # Arguments
///
/// * `port_payload_map` - A BTreeMap mapping port lists to their payload variants
fn generate_code(port_payload_map: BTreeMap<Vec<u16>, Vec<Vec<u8>>>) {
    let dest_path = PathBuf::from("src/generated.rs");

    let (payloads, ports) = index_payloads(port_payload_map);
    let ranges = coalesce_port_ranges(ports);

    let mut generated_code = String::new();
    for (index, payload) in payloads.iter().enumerate() {
        writeln!(
            generated_code,
            "static PAYLOAD_{index}: &[u8] = &{payload:?};"
        )
        .unwrap();
    }
    writeln!(
        generated_code,
        "/// Returns every distinct UDP probe for a port."
    )
    .unwrap();
    writeln!(
        generated_code,
        "/// Ports absent from the payload database return an empty slice."
    )
    .unwrap();
    writeln!(
        generated_code,
        "pub fn payloads_for(port: u16) -> &'static [&'static [u8]] {{"
    )
    .unwrap();
    writeln!(generated_code, "match port {{").unwrap();
    for (start, end, probes) in ranges {
        let probes = probes
            .iter()
            .map(|index| format!("PAYLOAD_{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            generated_code,
            "{start}..={end} => {{ static PROBES: &[&[u8]] = &[{probes}]; PROBES }},"
        )
        .unwrap();
    }
    writeln!(generated_code, "_ => &[],\n}}\n}}").unwrap();

    fs::write(dest_path, generated_code).unwrap();

    // format the generated code
    Command::new("cargo")
        .arg("fmt")
        .arg("--all")
        .output()
        .expect("Failed to execute cargo fmt");
}

/// Creates a BTreeMap of line numbers mapped to a Vec<u16> of ports
///
/// # Arguments
///
/// * `fp_map` - A BTreeMap containing the parsed file data
///
/// # Returns
///
/// A BTreeMap where keys are line numbers and values are vectors of ports
fn ports_v(fp_map: &BTreeMap<i32, String>) -> BTreeMap<i32, Vec<u16>> {
    let mut pb_linenr: BTreeMap<i32, Vec<u16>> = BTreeMap::new();
    let mut port_list: Vec<u16> = Vec::new();

    for (&line_nr, ports) in fp_map {
        if ports.contains("udp ") {
            let remain = &ports[4..];
            let mut start = remain.split(' ');

            let ports = start.next().unwrap();
            let port_segments: Vec<&str> = ports.split(',').collect();

            for segment in port_segments {
                if segment.contains('-') {
                    let range: Vec<&str> = segment.trim().split('-').collect();
                    let start = range[0].parse::<u16>().unwrap();
                    let end = range[1].parse::<u16>().unwrap();
                    assert!(start <= end, "reversed port range: {}", segment);

                    port_list.extend(start..=end);
                } else if !segment.is_empty() {
                    match segment.parse::<u16>() {
                        Ok(port) => port_list.push(port),
                        Err(_) => panic!("invalid port: {}", segment),
                    }
                }
            }
            port_list.sort_unstable();
            port_list.dedup();
        }

        pb_linenr.insert(line_nr, port_list.clone());
        port_list.clear();
    }

    pb_linenr
}

/// Parses out the Payloads into a BTreeMap of line numbers mapped to vectors of payload bytes
///
/// # Arguments
///
/// * `fp_map` - A BTreeMap containing the parsed file data
///
/// # Returns
///
/// A BTreeMap where keys are line numbers and values are vectors of payload bytes
fn payloads_v(fp_map: &BTreeMap<i32, String>) -> BTreeMap<i32, Vec<u8>> {
    let mut payb_linenr: BTreeMap<i32, Vec<u8>> = BTreeMap::new();

    for (&line_nr, data) in fp_map {
        if data.contains('"') {
            let start = data.find('"').expect("payload opening \" not found");
            // Pass from the opening quote: the decoder pairs quotes itself
            // to split multi-line segments.
            payb_linenr.insert(line_nr, parser(data[start..].trim()));
        }
    }

    payb_linenr
}

/// Converts a quoted Nmap payload block to bytes.
///
/// # Arguments
///
/// * `payload` - The raw block text starting at its first opening quote:
///   one or more `"..."` segments separated by whitespace
///
/// # Returns
///
/// The decoded probe bytes: segments are decoded with [`decode_segment`]
/// and concatenated with no separators, so multi-line probes reassemble
/// exactly.
fn parser(payload: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut rest = payload.trim();
    while let Some(open) = rest.find('"') {
        let after_open = &rest[open + 1..];
        match split_segment(after_open) {
            Some((segment, remainder)) => {
                decode_segment(segment, &mut bytes);
                rest = remainder;
            }
            None => {
                // Unterminated trailing quote: decode what's left literally.
                decode_segment(after_open, &mut bytes);
                break;
            }
        }
    }

    bytes
}

/// Splits off the first `"..."` segment: `text` must start just after an
/// opening quote. Escaped quotes (`\"`) do not terminate the segment.
///
/// Returns the segment body and the remainder after the closing quote.
fn split_segment(text: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (i, c) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            return Some((&text[..i], &text[i + 1..]));
        }
    }
    None
}

/// Decodes one quoted Nmap payload segment in C-style escape format:
/// `\xNN` becomes a byte, common single-char escapes (`\\`, `\"`,
/// `\0`, `\n`, `\r`, `\t`) decode to their value, and every other
/// character contributes its literal bytes.
///
/// Preserving literal text matters: several probes embed plain-text
/// protocol words (the SNMP `public` community string, NetBIOS names,
/// LDAP `objectClass`, SSDP headers). The previous hexdigits-only
/// decoding mangled them into wrong bytes, so agents never answered.
fn decode_segment(segment: &str, bytes: &mut Vec<u8>) {
    let mut chars = segment.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next() {
            Some('x') => {
                let hi = chars.next().unwrap_or('0');
                let lo = chars.next().unwrap_or('0');
                let hex: String = [hi, lo].iter().collect();
                bytes.push(u8::from_str_radix(&hex, 16).unwrap_or(0));
            }
            Some('0') => bytes.push(0),
            Some('n') => bytes.push(b'\n'),
            Some('r') => bytes.push(b'\r'),
            Some('t') => bytes.push(b'\t'),
            Some('\\') => bytes.push(b'\\'),
            Some('"') => bytes.push(b'"'),
            // Unknown escape: keep the character literally, matching Nmap,
            // which passes unrecognized escapes through untouched.
            Some(other) => {
                let mut buf = [0; 4];
                bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
            None => bytes.push(b'\\'),
        }
    }
}

/// Combines the ports BTreeMap and the Payloads BTreeMap
///
/// # Arguments
///
/// * `pb_linenr` - A BTreeMap mapping line numbers to vectors of ports
/// * `payb_linenr` - A BTreeMap mapping line numbers to vectors of payload bytes
///
/// # Returns
///
/// A BTreeMap mapping vectors of ports to their payload variants, in file
/// order. Entries that share a port list keep every distinct payload.
fn port_payload_map(
    pb_linenr: BTreeMap<i32, Vec<u16>>,
    payb_linenr: BTreeMap<i32, Vec<u8>>,
) -> BTreeMap<Vec<u16>, Vec<Vec<u8>>> {
    let mut ppm_fin: BTreeMap<Vec<u16>, Vec<Vec<u8>>> = BTreeMap::new();

    for (port_linenr, ports) in pb_linenr {
        for (pay_linenr, payloads) in &payb_linenr {
            if pay_linenr == &port_linenr {
                let variants = ppm_fin.entry(ports.to_vec()).or_default();
                if !variants.contains(payloads) {
                    variants.push(payloads.to_vec());
                }
            }
        }
    }

    ppm_fin
}
