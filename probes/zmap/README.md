# Supplemental ZMap discovery packets

These six `.pkt` files are copied byte-for-byte from
[ZMap commit 9c28f459fad8c6d77a0726106ced13c62a84e294](https://github.com/zmap/zmap/tree/9c28f459fad8c6d77a0726106ced13c62a84e294/examples/udp-probes).
The upstream Apache-2.0 license is included as `LICENSE`; `SHA256SUMS` pins each
packet. The upstream packet files carry no individual notices, and the pinned
source tree has no NOTICE file. ZMap's catalogue describes these as:

| File | UDP port | Purpose |
| --- | ---: | --- |
| chargen_19.pkt | 19 | Character Generator request |
| digi1_2362.pkt | 2362 | Digi ADDP, default magic |
| digi2_2362.pkt | 2362 | Digi ADDP, devkit magic |
| digi3_2362.pkt | 2362 | Digi ADDP, OEM magic |
| wsd_3702.pkt | 3702 | WS-Discovery device Probe |
| sentinel_5093.pkt | 5093 | Sentinel licence-manager discovery |

`build/supplemental_payloads.rs` appends these after the Nmap variants and also
constructs an independent QUIC probe from RFC 9000 sections 6.3 and 14.1.
No SQL Browser probe is added: Nmap's `no-payload` exclusion is preserved.
The malformed WSD probe is not imported.

ZMap's RDP candidate remains deferred: its 18-byte packet does not match the
[documented SYN construction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/066f9acf-fd57-4f95-ab3f-334e748bab10)
(including padding to the negotiated 1132–1232 byte MTU). A Windows service
fixture is needed before adding an RDP probe. Its QUIC candidate is also not
copied: the pinned file encodes version 1, although the upstream README describes
an unsupported version. Our QUIC probe uses reserved version `0x0a0a0a0a`, two
8-byte connection IDs, and zero padding to 1200 bytes. It requests Version
Negotiation only; it does not establish HTTP/3 support or complete TLS.

The committed loopback tests check delivery of each variant, retry counts,
closed/silent ports, and replies from another source port over IPv4 and IPv6.
QUIC is additionally tested against aioquic 1.3.0. Digi and Sentinel tests are
byte-selective fixtures, not physical-device validation. WSD is parsed as SOAP
and exercised as a byte-selective fixture; real-device discovery rates remain
unmeasured. These packets are draft candidates pending deployment validation.
