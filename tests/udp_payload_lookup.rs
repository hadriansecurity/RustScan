use rustscan::generated::get_parsed_data;
use rustscan::scanner::build_udp_payload_lookup;

#[test]
fn overlapping_entries_keep_all_variants_without_duplicate_packets() {
    use once_cell::sync::Lazy;
    use std::collections::BTreeMap;

    static ENTRIES: Lazy<BTreeMap<Vec<u16>, Vec<Vec<u8>>>> = Lazy::new(|| {
        BTreeMap::from([
            (
                vec![10, 11],
                vec![b"first".to_vec(), b"first".to_vec(), b"second".to_vec()],
            ),
            (vec![11, 12], vec![b"first".to_vec(), b"third".to_vec()]),
        ])
    });
    let lookup = build_udp_payload_lookup(&ENTRIES);
    assert_eq!(lookup[&10], [b"first".as_slice(), b"second"]);
    assert_eq!(lookup[&11], [b"first".as_slice(), b"second", b"third"]);
    assert_eq!(lookup[&12], [b"first".as_slice(), b"third"]);
    assert!(!lookup.contains_key(&13));
    assert!(std::ptr::eq(lookup[&10][0], lookup[&11][0]));
}

#[test]
fn udp_payload_lookup_contains_common_udp_ports() {
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);

    // These are common UDP services; the payload database should include them.
    assert!(
        lookup.contains_key(&53),
        "expected UDP payload for DNS (53)"
    );
    assert!(
        lookup.contains_key(&123),
        "expected UDP payload for NTP (123)"
    );
}

#[test]
fn udp_payload_lookup_payloads_are_non_empty_for_known_ports() {
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);

    // Don't assert exact bytes (the generated payload set may evolve),
    // but it should not be empty for these well-known protocols.
    let dns = lookup.get(&53).expect("missing DNS payload");
    assert!(!dns.is_empty() && dns.iter().all(|payload| !payload.is_empty()));

    let ntp = lookup.get(&123).expect("missing NTP payload");
    assert!(!ntp.is_empty() && ntp.iter().all(|payload| !payload.is_empty()));
}
