//! Pins the probe variants generated from `nmap-payloads`, so a parsing
//! regression shows up as lost coverage instead of silently missed services.

#[path = "../build.rs"]
mod build_script;

use build_script::parse;
use once_cell::sync::Lazy;
use rustscan::generated::get_parsed_data;
use rustscan::scanner::{build_udp_payload_lookup, UdpPayloadLookup};

static LOOKUP: Lazy<UdpPayloadLookup> = Lazy::new(|| build_udp_payload_lookup(get_parsed_data()));

fn payloads_for(port: u16) -> &'static [&'static [u8]] {
    LOOKUP.get(&port).map(Vec::as_slice).unwrap_or(&[])
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn comments_do_not_remove_payloads_or_literal_hashes() {
    let entries = parse(
        r##"
# comment with "unbalanced quotes
udp 623 # header comment
"a#b" # trailing comment
"\"#\\" # escaped quote and backslash before the closing quote
"\x80\0"
"##,
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].payload, b"a#b\"#\\\x80\0");
}

#[test]
fn ranges_include_both_endpoints_and_deduplicate_ports() {
    let entries = parse("udp 1198-1199,1199,65534-65535,8-8 \"probe\"").unwrap();
    assert_eq!(entries[0].ports, [8, 1198, 1199, 65534, 65535]);
}

#[test]
fn duplicate_and_overlapping_port_lists_preserve_every_entry() {
    let entries =
        parse("udp 53,123 \"first\"\nudp 53,123 \"second\"\nudp 123-124 \"third\"").unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].payload, b"first");
    assert_eq!(entries[1].payload, b"second");
    assert_eq!(entries[2].ports, [123, 124]);
    assert_eq!(entries[2].payload, b"third");
}

#[test]
fn flushes_single_and_final_entries_without_a_trailing_newline() {
    for input in ["udp 48899 \"ads\"", "udp 53 \"dns\"\nudp 48899 \"ads\""] {
        let entries = parse(input).unwrap();
        assert_eq!(entries.last().unwrap().ports, [48899]);
        assert_eq!(entries.last().unwrap().payload, b"ads");
    }
}

#[test]
fn accepts_indented_headers_tabs_and_multiline_entries() {
    let entries = parse("  udp\t53\n\"a\"\n\"b\"\n\tudp\n123\n\"c\"").unwrap();
    assert_eq!(entries[0].ports, [53]);
    assert_eq!(entries[0].payload, b"ab");
    assert_eq!(entries[1].ports, [123]);
    assert_eq!(entries[1].payload, b"c");
}

#[test]
fn invalid_entries_fail_with_the_source_line_instead_of_losing_coverage() {
    for entry in ["udp 2-1 \"x\"", "udp 65536 \"x\"", "udp 53", "tcp 53 \"x\""] {
        let error = parse(&format!("# comment\n{entry}")).unwrap_err();
        assert!(error.starts_with("line 2:"), "{}", error);
    }
}

#[test]
fn runtime_lookup_matches_every_vendored_entry_and_gap() {
    use std::collections::BTreeMap;
    let entries = parse(include_str!("../nmap-payloads")).unwrap();
    let mut expected: BTreeMap<u16, Vec<Vec<u8>>> = BTreeMap::new();
    for entry in entries {
        for port in entry.ports {
            let variants = expected.entry(port).or_default();
            if !variants.contains(&entry.payload) {
                variants.push(entry.payload.clone());
            }
        }
    }
    for port in 0..=u16::MAX {
        let mut variants: Vec<&[u8]> = expected
            .get(&port)
            .into_iter()
            .flatten()
            .map(Vec::as_slice)
            .collect();
        let mut actual = payloads_for(port).to_vec();
        actual.sort_unstable();
        variants.sort_unstable();
        assert_eq!(actual, variants, "udp/{port}");
    }
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
fn runtime_variants_are_unique_and_shared_across_ports() {
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
