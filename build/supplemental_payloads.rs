//! Curated additions; keep the pinned Nmap inputs and eligibility rules intact.

// RFC 9000 sections 6.3 and 14.1: a reserved version elicits Version
// Negotiation without completing a handshake; pad to the 1200-byte minimum.
// Only the version-independent long header is meaningful for this version.
// Fixed, distinct connection IDs suffice for discovery on a connected socket.
const fn quic_version_negotiation() -> [u8; 1200] {
    let header = *b"\xc0\x0a\x0a\x0a\x0a\x08rustscan\x08udp-prob";
    let mut packet = [0; 1200];
    let mut index = 0;
    while index < header.len() {
        packet[index] = header[index];
        index += 1;
    }
    packet
}

static QUIC: [u8; 1200] = quic_version_negotiation();

// The six ZMap files are unmodified. Provenance and hashes: probes/zmap/README.md.
// Append after Nmap so existing variants retain their ordering. SQL Browser
// remains excluded by Nmap's no-payload rule; RDP needs further validation.
pub static PROBES: &[(u16, &[u8])] = &[
    (19, include_bytes!("../probes/zmap/chargen_19.pkt")),
    (443, &QUIC),
    (2362, include_bytes!("../probes/zmap/digi1_2362.pkt")),
    (2362, include_bytes!("../probes/zmap/digi2_2362.pkt")),
    (2362, include_bytes!("../probes/zmap/digi3_2362.pkt")),
    (3702, include_bytes!("../probes/zmap/wsd_3702.pkt")),
    (5093, include_bytes!("../probes/zmap/sentinel_5093.pkt")),
];
