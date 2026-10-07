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

// Nmap's pinned IKE_MAIN_MODE request with the four-byte Non-ESP Marker
// required by RFC 3948 section 2.2 for UDP/4500. The IKE length excludes
// the marker. This is an IKEv1 Main Mode discovery request, not a VPN handshake.
// Source: nmap-service-probes at 24229f2e65aa11ca860b5c4ec6b4757dc2d8afd0;
// Nmap Software LLC, NPSL (see LICENSE.nmap). Keep the vendored file unchanged.
static IKE_NAT_T: &[u8] = b"\x00\x00\x00\x00\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\
    \x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xc0\
    \x00\x00\x00\xa4\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x98\
    \x01\x01\x00\x04\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\
    \x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0b\x00\x01\
    \x00\x0c\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x02\x01\x00\x00\
    \x80\x01\x00\x05\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02\
    \x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\
    \x03\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x02\x80\x03\x00\x01\
    \x80\x04\x00\x02\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x00\x01\
    \x00\x00\x00\x24\x04\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x01\
    \x80\x03\x00\x01\x80\x04\x00\x02\x80\x0b\x00\x01\x00\x0c\x00\x04\
    \x00\x00\x00\x01";

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
    (4500, IKE_NAT_T),
    (5093, include_bytes!("../probes/zmap/sentinel_5093.pkt")),
];
