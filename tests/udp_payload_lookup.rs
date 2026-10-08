use rustscan::generated::payloads_for;

#[test]
fn udp_payload_lookup_contains_common_udp_ports() {
    for port in [53, 123] {
        assert!(
            !payloads_for(port).is_empty(),
            "no payload for port {}",
            port
        );
    }
}

#[test]
fn udp_payload_lookup_payloads_are_non_empty_for_known_ports() {
    for port in [53, 123] {
        assert!(
            payloads_for(port).iter().all(|payload| !payload.is_empty()),
            "empty payload for port {}",
            port
        );
    }
}

#[test]
fn records_sharing_a_port_list_keep_every_variant() {
    assert_eq!(payloads_for(623).len(), 2, "ASF ping and IPMI");
    assert_eq!(payloads_for(161).len(), 2, "SNMPv3 and SNMPv1");
}

#[test]
fn port_ranges_include_their_last_port() {
    for port in [1199, 26004, 27030, 27914, 27964, 30724, 65535] {
        assert!(
            !payloads_for(port).is_empty(),
            "no payload for port {}",
            port
        );
    }
}

#[test]
fn the_last_record_in_the_file_is_kept() {
    assert!(payloads_for(48899)
        .iter()
        .any(|payload| payload.starts_with(&[0x03, 0x66, 0x14, 0x71])));
}

#[test]
fn trailing_comments_are_not_part_of_the_payload() {
    let asf_ping: &[u8] = &[
        0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x80, 0x00, 0x00, 0x00,
    ];
    assert!(payloads_for(623).contains(&asf_ping));
}

#[test]
fn static_storage_is_reused_across_lookups_and_overlapping_records() {
    assert!(std::ptr::eq(payloads_for(53), payloads_for(53)));
    assert!(std::ptr::eq(payloads_for(32768), payloads_for(32769)));
    // Nmap sends another RPC variant first on 32768; use the range-only port.
    let rpc = payloads_for(65535)[0];
    assert!(payloads_for(32768)
        .iter()
        .any(|probe| std::ptr::eq(*probe, rpc)));
    assert!(payloads_for(48899)
        .iter()
        .any(|probe| std::ptr::eq(*probe, rpc)));
}

#[test]
fn ports_without_a_payload_return_no_probes() {
    assert!(payloads_for(0).is_empty());
    assert!(payloads_for(1).is_empty());
}
