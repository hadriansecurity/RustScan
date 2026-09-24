//! The UDP payload table is generated from `nmap-payloads` at build time, so a
//! decoding mistake there is invisible until a scan silently stops finding a
//! protocol. These tests pin the bytes for probes whose payloads are written as
//! literal text rather than `\xNN` escapes, which is where decoding goes wrong.

#[path = "../build/payload.rs"]
mod payload_parser;

use rustscan::generated::payloads_for;

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
        "udp/161 payloads lost the community string: {:02x?}",
        payloads
    );
}

#[test]
fn snmp_probe_is_well_formed_ber() {
    let payload = payloads_for(161)
        .iter()
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
        assert!(
            !payloads.is_empty(),
            "no payload registered for udp/{}",
            port
        );
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
    // not regress into emitting the literal characters instead. Both variants
    // must survive generation.
    let payloads = payloads_for(123);
    assert!(!payloads.is_empty(), "no payload registered for udp/123");
    assert!(
        payloads.iter().any(|p| p.first() == Some(&0xE3))
            && payloads.iter().any(|p| p.first() == Some(&0xD9)),
        "udp/123 payload does not start with an NTP LI/VN/Mode byte: {:02x?}",
        payloads
    );
    assert!(
        payloads.iter().all(|p| !contains(p, b"\\x")),
        "a payload kept its escape sequence as literal text"
    );
}

#[test]
fn rmcp_asf_and_ipmi_both_survive_trailing_comments_and_shared_ports() {
    let payloads = payloads_for(623);
    assert!(payloads.contains(&b"\x06\0\xff\x06\0\0\x11\xbe\x80\0\0\0".as_slice()));
    assert!(payloads.iter().any(|p| p.starts_with(b"\x06\0\xff\x07")));
    assert_eq!(payloads.len(), 2);
}

#[test]
fn final_ads_entry_survives_alongside_the_overlapping_rpc_probe() {
    let payloads = payloads_for(48899);
    assert!(payloads.contains(
        &b"\x03\x66\x14\x71\0\0\0\0\x01\0\0\0\0\0\0\0\x01\x01\x10\x27\0\0\0\0".as_slice()
    ));
    assert!(payloads.iter().any(|p| p.len() == 40));
    assert_eq!(payloads.len(), 2);
}

#[test]
fn range_endpoints_have_the_same_probes_as_the_previous_port() {
    for end in [1199, 26004, 27030, 27914, 27964, 30724, 65535] {
        let payloads = payloads_for(end);
        assert!(!payloads.is_empty(), "missing udp/{}", end);
        assert_eq!(payloads, payloads_for(end - 1), "udp/{end}");
    }
}

#[test]
fn overlapping_dns_and_shared_snmp_keys_preserve_variants() {
    let dns = payloads_for(53);
    assert!(dns.contains(&b"\0\0\x10\0\0\0\0\0\0\0\0\0".as_slice()));
    assert!(dns.iter().any(|p| contains(p, b"version")));
    assert_eq!(dns.len(), 2);
    let snmp = payloads_for(161);
    assert!(snmp.iter().any(|p| p.starts_with(b"\x30\x3a\x02\x01\x03")));
    assert_eq!(snmp.len(), 2);
}

#[test]
fn generated_variants_are_unique_and_shared_across_ports() {
    for port in 0..=u16::MAX {
        let payloads = payloads_for(port);
        for (index, payload) in payloads.iter().enumerate() {
            assert!(!payloads[..index].contains(payload));
        }
    }
    let first = payloads_for(2049)[0];
    let last = payloads_for(65535)[0];
    assert!(
        std::ptr::eq(first, last),
        "RPC payload bytes must be shared across separate port ranges"
    );
}

#[test]
fn vendored_database_coverage_and_packet_budget_are_preserved() {
    let counts: Vec<_> = (0..=u16::MAX)
        .map(|port| payloads_for(port).len())
        .collect();
    let actual = (
        counts.iter().filter(|&&count| count > 0).count(),
        counts.iter().sum::<usize>(),
        counts.iter().filter(|&&count| count > 1).count(),
        counts.iter().max().copied(),
    );
    assert_eq!(
        actual,
        (33_053, 33_077, 20, Some(4)),
        "probe coverage changed: investigate lost probes or update after syncing nmap-payloads"
    );
}
