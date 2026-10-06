use std::{collections::BTreeMap, fmt::Write};

pub fn generate(entries: Vec<Entry>) -> String {
    // Resolve overlaps and share payloads at build time. Even a one-port scan
    // can then borrow static probes without building a 33,000-entry heap map.
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
    code
}

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub ports: Vec<u16>,
    pub payload: Vec<u8>,
}

/// Nmap's payload.cc selects UDP probes not marked `no-payload`, using only
/// their ordinary `ports` list. `sslports`, `Exclude`, rarity and match rules
/// belong to version detection and do not restrict UDP discovery payloads.
pub fn parse_service_probes(input: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    for (offset, line) in input.lines().enumerate() {
        let line = line.trim();
        let error = |message: &str| format!("line {}: {message}", offset + 1);
        let (directive, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        match directive {
            "Probe" => {
                if let Some(entry) = current.take().filter(|entry| !entry.ports.is_empty()) {
                    entries.push(entry);
                }
                let (protocol, rest) = rest
                    .trim_start()
                    .split_once(char::is_whitespace)
                    .ok_or_else(|| error("expected probe protocol and name"))?;
                if protocol == "TCP" {
                    continue;
                }
                if protocol != "UDP" {
                    return Err(error("expected TCP or UDP probe"));
                }
                let (_, quoted) = rest
                    .trim_start()
                    .split_once(char::is_whitespace)
                    .ok_or_else(|| error("expected probe name and q-delimited payload"))?;
                let quoted = quoted
                    .trim_start()
                    .strip_prefix('q')
                    .ok_or_else(|| error("expected q-delimited payload"))?;
                let delimiter = quoted
                    .chars()
                    .next()
                    .ok_or_else(|| error("missing payload delimiter"))?;
                // Nmap uses strchr: even a backslash does not escape the
                // delimiter. Embedded delimiter bytes must use hex escapes.
                let (body, flags) = quoted[delimiter.len_utf8()..]
                    .split_once(delimiter)
                    .ok_or_else(|| error("unterminated probe payload"))?;
                let payload = decode_service_payload(body).map_err(|message| error(&message))?;
                if !flags
                    .split_whitespace()
                    .any(|flag| flag.starts_with("no-payload"))
                {
                    current = Some(Entry {
                        ports: Vec::new(),
                        payload,
                    });
                }
            }
            "ports" => {
                if let Some(entry) = &mut current {
                    entry.ports.extend(parse_ports(rest.trim(), offset + 1)?);
                }
            }
            _ => {}
        }
    }
    if let Some(entry) = current.filter(|entry| !entry.ports.is_empty()) {
        entries.push(entry);
    }
    Ok(entries)
}

/// Strictly match utils.cc::cstring_unescape, which supports only these
/// escapes for service probes (not C's octal, Unicode or arbitrary escapes).
fn decode_service_payload(body: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut bytes = body.bytes();
    while let Some(byte) = bytes.next() {
        result.push(if byte == b'\\' {
            match bytes.next() {
                Some(b'\\') => b'\\',
                Some(b'0') => 0,
                Some(b'n') => b'\n',
                Some(b'r') => b'\r',
                Some(b't') => b'\t',
                Some(b'x') => {
                    let mut digit = || {
                        bytes
                            .next()
                            .and_then(|b| (b as char).to_digit(16))
                            .ok_or_else(|| "invalid hex escape".to_string())
                    };
                    (digit()? * 16 + digit()?) as u8
                }
                _ => return Err("unsupported or incomplete probe escape".to_string()),
            }
        } else {
            byte
        });
    }
    Ok(result)
}

fn parse_ports(spec: &str, line: usize) -> Result<Vec<u16>, String> {
    let error = |message: &str| format!("line {line}: {message}");
    let mut ports = Vec::new();
    for segment in spec.split(',') {
        let port = |value: &str| {
            value
                .trim()
                .parse::<u16>()
                .map_err(|_| error(&format!("invalid port {value:?}")))
        };
        if let Some((start, end)) = segment.split_once('-') {
            let (start, end) = (port(start)?, port(end)?);
            if start > end {
                return Err(error("reversed port range"));
            }
            ports.extend(start..=end);
        } else {
            ports.push(port(segment)?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}
