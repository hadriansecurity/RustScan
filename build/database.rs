//! Read Nmap's legacy payload database without losing entries or variants.
use crate::payload_parser::decode_payload;

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub ports: Vec<u16>,
    pub payload: Vec<u8>,
}

pub fn parse(input: &str) -> Result<Vec<Entry>, String> {
    let mut records = Vec::new();
    let mut current = String::new();
    let mut start_line = 0;
    for (offset, line) in input.lines().enumerate() {
        let line = without_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if line.split_whitespace().next() == Some("udp") {
            if !current.is_empty() {
                records.push(parse_entry(&current, start_line)?);
                current.clear();
            }
            start_line = offset + 1;
        } else if current.is_empty() {
            return Err(format!("line {}: expected udp entry", offset + 1));
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        records.push(parse_entry(&current, start_line)?);
    }
    Ok(records)
}

fn without_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else {
            match byte {
                b'\\' if quoted => escaped = true,
                b'"' => quoted = !quoted,
                b'#' if !quoted => return &line[..index],
                _ => {}
            }
        }
    }
    line
}

fn parse_entry(record: &str, line: usize) -> Result<Entry, String> {
    let error = |message: &str| format!("line {line}: {message}");
    let rest = record.strip_prefix("udp").unwrap().trim_start();
    let (spec, payload) = rest
        .split_once(char::is_whitespace)
        .ok_or_else(|| error("expected ports and quoted payload"))?;
    let mut ports = Vec::new();
    for segment in spec.split(',') {
        let port = |value: &str| {
            value
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
    Ok(Entry {
        ports,
        payload: decode_payload(payload).map_err(error)?,
    })
}
