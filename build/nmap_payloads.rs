//! Read Nmap's legacy payload database without losing entries or variants.

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
    let payload = payload
        .find('"')
        .map(|start| &payload[start..])
        .ok_or_else(|| error("expected a quoted payload"))?;
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
        payload: parser(payload),
    })
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
pub fn parser(payload: &str) -> Vec<u8> {
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
