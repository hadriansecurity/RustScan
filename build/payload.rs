/// Decode consecutive quoted strings, stopping before optional entry metadata.
pub fn decode_payload(input: &str) -> Result<Vec<u8>, &'static str> {
    let input = input.trim_start();
    if !input.starts_with('"') {
        return Err("expected a quoted payload");
    }

    let mut input = input.bytes().peekable();
    let mut payload = Vec::new();

    loop {
        while input.next_if(u8::is_ascii_whitespace).is_some() {}
        if input.next_if_eq(&b'"').is_none() {
            return Ok(payload);
        }

        loop {
            match input.next().ok_or("unterminated payload string")? {
                b'"' => break,
                b'\\' => payload.push(decode_escape(&mut input)?),
                byte => payload.push(byte),
            }
        }
    }
}

fn decode_escape(input: &mut impl Iterator<Item = u8>) -> Result<u8, &'static str> {
    match input.next().ok_or("incomplete escape")? {
        b'x' => {
            let mut byte = 0;
            for _ in 0..2 {
                let digit = input
                    .next()
                    .and_then(|byte| char::from(byte).to_digit(16))
                    .ok_or("expected two hex digits after \\x")?;
                byte = byte * 16 + digit as u8;
            }
            Ok(byte)
        }
        b'n' => Ok(b'\n'),
        b'r' => Ok(b'\r'),
        b't' => Ok(b'\t'),
        b'0' => Ok(0),
        b'\\' => Ok(b'\\'),
        b'"' => Ok(b'"'),
        _ => Err("unsupported escape"),
    }
}

#[cfg(test)]
mod tests {
    use super::decode_payload;

    #[test]
    fn preserves_literal_bytes_and_decodes_hex_pairs() {
        assert_eq!(
            decode_payload(r#""\x04\x06public\xa1\xFF0""#).unwrap(),
            b"\x04\x06public\xa1\xff0"
        );
    }

    #[test]
    fn concatenates_strings_without_losing_literal_whitespace() {
        assert_eq!(
            decode_payload("  \" public \"\n\t\"\"\"name \"  ").unwrap(),
            b" public name "
        );
    }

    #[test]
    fn decodes_escapes_without_treating_escaped_quotes_as_delimiters() {
        assert_eq!(
            decode_payload(r#""\0\r\n\t\\\"public\"""#).unwrap(),
            b"\0\r\n\t\\\"public\""
        );
    }

    #[test]
    fn stops_before_metadata_even_when_it_contains_quotes() {
        assert_eq!(
            decode_payload(r#""public" source 161 future "metadata""#).unwrap(),
            b"public"
        );
    }

    #[test]
    fn rejects_malformed_payloads() {
        for input in [
            "",
            "public",
            "\"public",
            "\"public\" \"unfinished",
            "\"\\",
            r#""\q""#,
            r#""\x""#,
            r#""\x0""#,
            r#""\xGG""#,
            r#""\x0" "1""#,
            r#""public\""#,
        ] {
            assert!(decode_payload(input).is_err(), "accepted {:?}", input);
        }
    }
}
