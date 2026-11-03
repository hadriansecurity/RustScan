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
// Requests of the fluentd and twamp plugins in hadriansecurity/fingerprintx#105.
// Fluentd answers any datagram with a NUL byte, so the request is not one.
static FLUENTD_HEARTBEAT: &[u8] = b"\x01";
// RFC 5357 unauthenticated test packet (sequence number, timestamp, error
// estimate), zero-padded to the 41-byte length a reflector sends back.
static TWAMP_TEST_PACKET: &[u8] = b"\x66\x78\x00\x01\xed\x5b\x2c\x00\x00\x00\x00\x00\x00\x01\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00";

// Requests of the ethernetip, hartip, dnp3 and melsec-q UDP plugins in
// hadriansecurity/fingerprintx#142.
// Nmap's enip-info List Identity; Nmap only sends ONCRPC_CALL to 44818.
static ENIP_LIST_IDENTITY: &[u8] = b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \xc1\xde\xbe\xd1\x00\x00\x00\x00\x00\x00\x00\x00";
// Session Initiate with a 20 s inactivity timer: the session is never closed,
// and devices allow only a few.
static HARTIP_SESSION_INITIATE: &[u8] = b"\x01\x00\x00\x00\x52\x53\x00\x0d\x01\x00\x00\x4e\x20";
// The plcscan melsecq-discover-udp CPU info request, as a real Q03UDECPU
// receives it; the length field (0x0014) counts the 20 bytes after offset 21.
static MELSEC_CPU_INFO: &[u8] = b"\x57\x00\x00\x00\x00\x11\x11\x07\x00\x00\xff\xff\x03\x00\x00\xfe\
    \x03\x00\x00\x14\x00\x1c\x08\x0a\x08\x00\x00\x00\x00\x00\x00\x00\x04\x01\x01\x01\
    \x00\x00\x00\x00\x01";

// An outstation answers only frames from its configured master to its own
// address, so one datagram carries Request Link Status for every likely pair.
const DNP3_MASTERS: [u16; 6] = [1, 0, 2, 3, 100, 1024];
const DNP3_OUTSTATIONS: [u16; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 1024, 0xfffc];
const DNP3_FRAME_LEN: usize = 10;
const DNP3_PROBE_LEN: usize = DNP3_MASTERS.len() * DNP3_OUTSTATIONS.len() * DNP3_FRAME_LEN;

// IEEE 1815 CRC: reflected polynomial 0xA6BC, complemented.
const fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    let mut i = 0;
    while i < data.len() {
        crc ^= data[i] as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa6bc
            } else {
                crc >> 1
            };
            bit += 1;
        }
        i += 1;
    }
    !crc
}

const fn dnp3_request_link_status() -> [u8; DNP3_PROBE_LEN] {
    let mut probe = [0; DNP3_PROBE_LEN];
    let mut offset = 0;
    let mut m = 0;
    while m < DNP3_MASTERS.len() {
        let mut o = 0;
        while o < DNP3_OUTSTATIONS.len() {
            let (dst, src) = (DNP3_OUTSTATIONS[o], DNP3_MASTERS[m]);
            // DIR and PRM set, function 9 (Request Link Status), no user data.
            let header = [
                0x05,
                0x64,
                0x05,
                0xc9,
                dst as u8,
                (dst >> 8) as u8,
                src as u8,
                (src >> 8) as u8,
            ];
            let crc = dnp3_crc(&header);
            let mut i = 0;
            while i < header.len() {
                probe[offset + i] = header[i];
                i += 1;
            }
            probe[offset + 8] = crc as u8;
            probe[offset + 9] = (crc >> 8) as u8;
            offset += DNP3_FRAME_LEN;
            o += 1;
        }
        m += 1;
    }
    probe
}

static DNP3_REQUEST_LINK_STATUS: [u8; DNP3_PROBE_LEN] = dnp3_request_link_status();

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
    (862, TWAMP_TEST_PACKET),
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
    (5006, MELSEC_CPU_INFO),
    (5093, include_bytes!("../probes/zmap/sentinel_5093.pkt")),
    (5094, HARTIP_SESSION_INITIATE),
    (5783, COAP_WELL_KNOWN_CORE),
    (8805, PFCP_HEARTBEAT),
    (9600, OMRON_FINS_CONTROLLER_DATA_READ),
    (20000, &DNP3_REQUEST_LINK_STATUS),
    (24224, FLUENTD_HEARTBEAT),
    (34980, ETHERCAT_BROADCAST_READ),
    (44818, ENIP_LIST_IDENTITY),
    (47808, BACNET_WHO_IS),
];
