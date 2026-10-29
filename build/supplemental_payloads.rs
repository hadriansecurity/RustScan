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

// Requests sent by the hadriansecurity/fingerprintx UDP plugins at 64ef00c (the
// version service-recognizer pins), so discovery reaches the ports those plugins
// identify. Fixed values replace the plugins' random IDs; a reply only needs to
// reach the scanner's socket.
static BACNET_WHO_IS: &[u8] = b"\x81\x0a\x00\x08\x01\x00\x10\x08";
// Nmap's coap-request, also the LwM2M plugin's request on the bootstrap port.
static COAP_WELL_KNOWN_CORE: &[u8] = b"@\x01\x01\xce\xbb.well-known\x04core";
// Frame type 1 (commands) sits in bits 12-15 of the header. fingerprintx sets
// bit 14 instead, which encodes type 4 (network variables).
static ETHERCAT_BROADCAST_READ: &[u8] = b"\x0c\x10\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static IAX2_POKE: &[u8] = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x1e";
static KNXNET_IP_SEARCH: &[u8] = b"\x06\x10\x02\x01\x00\x0e\x08\x01\x00\x00\x00\x00\x00\x00";
static MEGACO_SERVICE_CHANGE: &[u8] = b"MEGACO/1 [0.0.0.0]\nTransaction = 1 {\n  Context = - {\n    ServiceChange = ROOT {\n      Services {\n        Method = Restart,\n        Reason = \"901 Cold Boot\"\n      }\n    }\n  }\n}\n";
// AUEP is a call agent command, so call agents on 2727 may not answer it.
static MGCP_AUDIT_ENDPOINT: &[u8] = b"AUEP 9 * MGCP 1.0\r\n\r\n";
static OMRON_FINS_CONTROLLER_DATA_READ: &[u8] =
    b"\x80\x00\x02\x00\x00\x00\x00\x63\x00\xef\x05\x01\x00";
static PFCP_HEARTBEAT: &[u8] = b"\x20\x01\x00\x0c\x00\x00\x01\x00\x00\x60\x00\x04\x00\x00\x00\x01";
// GTP' v1 Echo Request with the 6-octet header (TS 32.295 section 6.1).
static GTP_PRIME_ECHO: &[u8] = b"\x2e\x01\x00\x00\x00\x00";

// fingerprintx's IKEv2 IKE_SA_INIT (RFC 7296): AES-CBC, SHA2/SHA1, DH group 14.
// Any value in [2, p-2] is a valid group 14 public key, so a fixed fill works.
const IKEV2_SA_INIT_LEN: usize = 420;
const fn ikev2_sa_init(initiator_spi: [u8; 8]) -> [u8; IKEV2_SA_INIT_LEN] {
    let header = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x21\x20\x22\x08\x00\x00\x00\x00\
    \x00\x00\x01\xa4\x22\x00\x00\x5c\x02\x00\x00\x2c\x01\x01\x00\x04\
    \x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x01\x00\x03\x00\x00\x08\
    \x03\x00\x00\x0c\x03\x00\x00\x08\x02\x00\x00\x05\x00\x00\x00\x08\
    \x04\x00\x00\x0e\x00\x00\x00\x2c\x02\x01\x00\x04\x03\x00\x00\x0c\
    \x01\x00\x00\x0c\x80\x0e\x00\x80\x03\x00\x00\x08\x03\x00\x00\x02\
    \x03\x00\x00\x08\x02\x00\x00\x02\x00\x00\x00\x08\x04\x00\x00\x0e\
    \x28\x00\x01\x08\x00\x0e\x00\x00";
    let nonce_header = *b"\x00\x00\x00\x24";
    let key_exchange_start = initiator_spi.len() + header.len();
    let nonce_header_start = key_exchange_start + 256;
    let mut packet = [0; IKEV2_SA_INIT_LEN];
    let mut index = 0;
    while index < IKEV2_SA_INIT_LEN {
        packet[index] = if index < initiator_spi.len() {
            initiator_spi[index]
        } else if index < key_exchange_start {
            header[index - initiator_spi.len()]
        } else if index < nonce_header_start {
            0x5a
        } else if index < nonce_header_start + nonce_header.len() {
            nonce_header[index - nonce_header_start]
        } else {
            0xa5
        };
        index += 1;
    }
    packet
}

// RFC 3948 section 2.2: IKE on UDP/4500 follows a four-byte Non-ESP Marker.
const fn with_non_esp_marker(message: [u8; IKEV2_SA_INIT_LEN]) -> [u8; IKEV2_SA_INIT_LEN + 4] {
    let mut packet = [0; IKEV2_SA_INIT_LEN + 4];
    let mut index = 0;
    while index < IKEV2_SA_INIT_LEN {
        packet[4 + index] = message[index];
        index += 1;
    }
    packet
}

static IKEV2_SA_INIT: [u8; IKEV2_SA_INIT_LEN] = ikev2_sa_init(*b"rustscan");
// With the same SPI, libreswan treats the second copy as a retransmit of the
// first and answers only one of 500 and 4500.
static IKEV2_SA_INIT_NAT_T: [u8; IKEV2_SA_INIT_LEN + 4] =
    with_non_esp_marker(ikev2_sa_init(*b"rustscnT"));

// The six ZMap files are unmodified. Provenance and hashes: probes/zmap/README.md.
// Append after Nmap so existing variants retain their ordering. SQL Browser
// remains excluded by Nmap's no-payload rule; RDP needs further validation.
pub static PROBES: &[(u16, &[u8])] = &[
    (19, include_bytes!("../probes/zmap/chargen_19.pkt")),
    (443, &QUIC),
    (500, &IKEV2_SA_INIT),
    (2362, include_bytes!("../probes/zmap/digi1_2362.pkt")),
    (2362, include_bytes!("../probes/zmap/digi2_2362.pkt")),
    (2362, include_bytes!("../probes/zmap/digi3_2362.pkt")),
    (2427, MGCP_AUDIT_ENDPOINT),
    (2727, MGCP_AUDIT_ENDPOINT),
    (2944, MEGACO_SERVICE_CHANGE),
    (2945, MEGACO_SERVICE_CHANGE),
    (3386, GTP_PRIME_ECHO),
    (3671, KNXNET_IP_SEARCH),
    (3702, include_bytes!("../probes/zmap/wsd_3702.pkt")),
    (4500, IKE_NAT_T),
    (4500, &IKEV2_SA_INIT_NAT_T),
    (4569, IAX2_POKE),
    (5093, include_bytes!("../probes/zmap/sentinel_5093.pkt")),
    (5783, COAP_WELL_KNOWN_CORE),
    (8805, PFCP_HEARTBEAT),
    (9600, OMRON_FINS_CONTROLLER_DATA_READ),
    (34980, ETHERCAT_BROADCAST_READ),
    (47808, BACNET_WHO_IS),
];
