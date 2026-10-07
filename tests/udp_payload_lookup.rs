use rustscan::generated::get_parsed_data;
use rustscan::scanner::build_udp_payload_lookup;

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
    assert!(!dns.is_empty(), "DNS payload should not be empty");

    let ntp = lookup.get(&123).expect("missing NTP payload");
    assert!(!ntp.is_empty(), "NTP payload should not be empty");
}

fn variants_for(port: u16) -> Vec<&'static Vec<u8>> {
    get_parsed_data()
        .iter()
        .filter(|(ports, _)| ports.contains(&port))
        .flat_map(|(_, variants)| variants)
        .collect()
}

#[test]
fn every_payload_record_in_nmap_payloads_is_kept() {
    let records = include_str!("../nmap-payloads")
        .lines()
        .filter(|line| line.starts_with("udp"))
        .count();
    let variants: usize = get_parsed_data().values().map(Vec::len).sum();

    assert_eq!(variants, records);
}

#[test]
fn records_sharing_a_port_list_keep_every_variant() {
    assert_eq!(variants_for(623).len(), 2, "ASF ping and IPMI");
    assert_eq!(variants_for(161).len(), 2, "SNMPv3 and SNMPv1");
}

#[test]
fn port_ranges_include_their_last_port() {
    for port in [1199, 27914, 65535] {
        assert!(
            !variants_for(port).is_empty(),
            "no payload for port {}",
            port
        );
    }
}

#[test]
fn the_last_record_in_the_file_is_kept() {
    let ads_discovery = variants_for(48899)
        .into_iter()
        .any(|payload| payload.starts_with(&[0x03, 0x66, 0x14, 0x71]));

    assert!(ads_discovery, "no Beckhoff ADS discovery payload for 48899");
}

#[test]
fn trailing_comments_are_not_part_of_the_payload() {
    let asf_ping: Vec<u8> = vec![
        0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x80, 0x00, 0x00, 0x00,
    ];

    assert!(variants_for(623).contains(&&asf_ping));
}

#[test]
fn lookup_sends_the_last_variant_of_a_record() {
    let lookup = build_udp_payload_lookup(get_parsed_data());
    let last = variants_for(623)
        .last()
        .copied()
        .expect("no payload for 623");

    assert_eq!(lookup.get(&623).copied(), Some(last.as_slice()));
}
