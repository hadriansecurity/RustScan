//! The UDP payload table is generated from `nmap-payloads` at build time, so a
//! decoding mistake there is invisible until a scan silently stops finding a
//! protocol. These tests pin the bytes for probes whose payloads are written as
//! literal text rather than `\xNN` escapes, which is where decoding goes wrong.

use rustscan::generated::get_parsed_data;

/// Every payload registered for `port`.
fn payloads_for(port: u16) -> Vec<&'static [u8]> {
    get_parsed_data()
        .iter()
        .filter(|(ports, _)| ports.contains(&port))
        .map(|(_, payload)| payload.as_slice())
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn snmp_probe_carries_the_community_string() {
    let payloads = payloads_for(161);
    assert!(!payloads.is_empty(), "no payload registered for udp/161");

    // The v1 GetRequest spells its community out as `public`. Dropping the
    // non-hex characters leaves 0xbc, and the BER length prefix then describes
    // an octet string longer than the message -- agents discard it in silence.
    assert!(
        payloads.iter().any(|p| contains(p, b"public")),
        "udp/161 payloads lost the community string: {payloads:02x?}"
    );
}

#[test]
fn snmp_probe_is_well_formed_ber() {
    let payload = payloads_for(161)
        .into_iter()
        .find(|p| contains(p, b"public"))
        .expect("no SNMP payload carrying a community string");

    // SEQUENCE, then a length covering everything after the two-byte header.
    assert_eq!(payload[0], 0x30, "SNMP probe must open with a BER SEQUENCE");
    assert_eq!(
        usize::from(payload[1]),
        payload.len() - 2,
        "declared BER length does not match the bytes on the wire"
    );
}

#[test]
fn netbios_probe_carries_the_wildcard_name() {
    let payloads = payloads_for(137);
    assert!(!payloads.is_empty(), "no payload registered for udp/137");
    assert!(
        payloads
            .iter()
            .any(|p| contains(p, b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
        "udp/137 payloads lost the encoded wildcard name"
    );
}

#[test]
fn text_probes_survive_decoding() {
    for (port, needle) in [
        (1900u16, b"M-SEARCH * HTTP/1.1".as_slice()),
        (389, b"objectClass".as_slice()),
        (11211, b"version".as_slice()),
        (427, b"service:service-agent".as_slice()),
    ] {
        let payloads = payloads_for(port);
        assert!(!payloads.is_empty(), "no payload registered for udp/{port}");
        assert!(
            payloads.iter().any(|p| contains(p, needle)),
            "udp/{port} payload lost {:?}",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn escape_sequences_still_decode_to_single_bytes() {
    // udp/123's NTP probes are pure `\xNN`, so they pin that the escape path did
    // not regress into emitting the literal characters instead. Two variants are
    // registered for the port and only one currently survives the port-keyed map,
    // so accept either first byte rather than depending on which one wins.
    let payloads = payloads_for(123);
    assert!(!payloads.is_empty(), "no payload registered for udp/123");
    assert!(
        payloads
            .iter()
            .any(|p| matches!(p.first(), Some(0xE3 | 0xD9))),
        "udp/123 payload does not start with an NTP LI/VN/Mode byte: {payloads:02x?}"
    );
    assert!(
        payloads.iter().all(|p| !contains(p, b"\\x")),
        "a payload kept its escape sequence as literal text"
    );
}
