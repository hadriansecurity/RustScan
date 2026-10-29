"""Supplemental UDP wire tests (fixtures, not real Digi/Sentinel devices).

Run in an isolated Linux network namespace, as root:
  unshare --net python3 tests/udp_supplemental_probes.py target/debug/rustscan
"""
import collections
import hashlib
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import unittest
import xml.etree.ElementTree as ET

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
VENDOR = pathlib.Path(__file__).resolve().parents[1] / "probes/zmap"
QUIC = b"\xc0\x0a\x0a\x0a\x0a\x08rustscan\x08udp-prob" + bytes(1177)


# Independently encode the IKEv1 SA proposal (RFC 2408/2409), then add
# the Non-ESP Marker (RFC 3948 section 2.2). Do not load the Rust probe bytes.
def ike_natt_request():
    transforms = []
    for index, (cipher, digest) in enumerate([(5, 2), (5, 1), (1, 2), (1, 1)], 1):
        attributes = struct.pack("!10H", 0x8001, cipher, 0x8002, digest,
                                 0x8003, 1, 0x8004, 2, 0x800b, 1)
        attributes += struct.pack("!HHI", 0x000c, 4, 1)  # One-second lifetime.
        transforms.append(struct.pack("!BBHBBBB", 3 if index < 4 else 0,
                                      0, 36, index, 1, 0, 0) + attributes)
    proposal = struct.pack("!BBHBBBB", 0, 0, 152, 1, 1, 0, 4) + b"".join(transforms)
    sa = struct.pack("!BBHII", 0, 0, 164, 1, 1) + proposal
    header = struct.pack("!QQBBBBII", 0x0011223344556677, 0, 1, 0x10, 2, 0, 0, 192)
    return bytes(4) + header + sa


IKE_NAT_T = ike_natt_request()


# Independently encode fingerprintx's IKEv2 IKE_SA_INIT (RFC 7296).
def ikev2_sa_init(initiator_spi):
    def proposal(number, key_bits, integrity, prf):
        transforms = [(1, 12, struct.pack("!HH", 0x800e, key_bits)), (3, integrity, b""),
                      (2, prf, b""), (4, 14, b"")]
        body = b"".join(struct.pack("!BBHBBH", 3 if index < 3 else 0, 0, 8 + len(attributes),
                                    kind, 0, ident) + attributes
                        for index, (kind, ident, attributes) in enumerate(transforms))
        return struct.pack("!BBHBBBB", 2 if number == 1 else 0, 0, 8 + len(body),
                           number, 1, 0, 4) + body
    proposals = proposal(1, 256, 12, 5) + proposal(2, 128, 2, 2)
    sa = struct.pack("!BBH", 34, 0, 4 + len(proposals)) + proposals
    ke = struct.pack("!BBHHH", 40, 0, 264, 14, 0) + b"\x5a" * 256
    nonce = struct.pack("!BBH", 0, 0, 36) + b"\xa5" * 32
    body = sa + ke + nonce
    return initiator_spi + bytes(8) + struct.pack("!BBBBII", 33, 0x20, 34, 8, 0, 28 + len(body)) + body


IKEV2 = ikev2_sa_init(b"rustscan")
MEGACO = (b"MEGACO/1 [0.0.0.0]\nTransaction = 1 {\n  Context = - {\n"
          b"    ServiceChange = ROOT {\n      Services {\n        Method = Restart,\n"
          b"        Reason = \"901 Cold Boot\"\n      }\n    }\n  }\n}\n")
PROBES = {
    19: [b"\x01"],
    443: [QUIC],
    2362: [magic + bytes.fromhex("00010006ffffffffffff")
           for magic in [b"DIGI", b"DVKT", b"DGDP"]],
    3702: [(VENDOR / "wsd_3702.pkt").read_bytes()],
    500: [IKEV2],
    4500: [IKE_NAT_T, bytes(4) + ikev2_sa_init(b"rustscnT")],
    5093: [b"\x7a" + bytes(5)],
    # Requests sent by the matching fingerprintx plugins.
    2427: [b"AUEP 9 * MGCP 1.0\r\n\r\n"],
    2727: [b"AUEP 9 * MGCP 1.0\r\n\r\n"],
    2944: [MEGACO],
    3386: [bytes.fromhex("2e01 0000 0000")],
    2945: [MEGACO],
    3671: [bytes.fromhex("0610 0201 000e 0801 00000000 0000")],
    4569: [bytes.fromhex("8000 0000 00000000 00 00 06 1e")],
    5783: [b"@\x01\x01\xce\xbb.well-known\x04core"],
    8805: [bytes.fromhex("20 01 000c 000001 00 0060 0004 00000001")],
    9600: [bytes.fromhex("80 00 02 00 00 00 00 63 00 ef 05 01 00")],
    34980: [bytes.fromhex("0c10 07 00 0000 0000 0000 0000 0000")],
    47808: [bytes.fromhex("810a 0008 0100 1008")],
}
# Includes the retained Nmap variants on 443, 500, 2427, 3386, 34980 and 47808.
VARIANTS = {19: 1, 443: 4, 500: 5, 2362: 3, 3386: 2, 3702: 1, 4500: 2, 5093: 1,
            2427: 2, 2727: 1, 2944: 1, 2945: 1, 3671: 1, 4569: 1, 5783: 1,
            8805: 1, 9600: 1, 34980: 2, 47808: 2}


def scan(port, host):
    result = subprocess.run(
        [BINARY, "--no-config", "--addresses", host, "--ports", str(port),
         "--udp", "--greppable", "--timeout", "200", "--tries", "2"],
        text=True, capture_output=True, check=True, timeout=5,
    )
    return f"{host} -> [{port}]" in result.stdout


class SupplementalProbes(unittest.TestCase):
    def test_vendor_hashes_and_wsd_structure(self):
        for line in (VENDOR / "SHA256SUMS").read_text().splitlines():
            expected, filename = line.split()
            self.assertEqual(hashlib.sha256((VENDOR / filename).read_bytes()).hexdigest(),
                             expected, filename)
        namespaces = {"s": "http://www.w3.org/2003/05/soap-envelope",
                      "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
                      "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery"}
        root = ET.fromstring(PROBES[3702][0])
        self.assertEqual(root.find("s:Header/a:Action", namespaces).text,
                         namespaces["d"] + "/Probe")
        self.assertIsNotNone(root.find("s:Body/d:Probe", namespaces))

    def fixture(self, family, host, port, accepted, response):
        with socket.socket(family, socket.SOCK_DGRAM) as server, \
                socket.socket(family, socket.SOCK_DGRAM) as alternate:
            server.bind((host, port))
            alternate.bind((host, 0))
            server.settimeout(0.05)
            stopped = threading.Event()
            received = []

            def serve():
                while not stopped.is_set():
                    try:
                        payload, peer = server.recvfrom(4096)
                    except socket.timeout:
                        continue
                    received.append(payload)
                    if payload == accepted:
                        if response == "same-peer":
                            server.sendto(b"reply", peer)
                        elif response == "other-peer":
                            alternate.sendto(b"reply", peer)

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                found = scan(port, host)
            finally:
                stopped.set()
                worker.join(timeout=2)
            self.assertIn(accepted, received)
            self.assertNotIn(b"", received)
            self.assertEqual(found, response == "same-peer")
            if response != "same-peer":
                # Assert the actual retry budget, including preexisting probes.
                self.assertEqual(len(received), VARIANTS[port] * 2)
                self.assertEqual(len(set(received)), VARIANTS[port])
                self.assertEqual(set(collections.Counter(received).values()), {2})
                for probe in PROBES[port]:
                    self.assertIn(probe, received)

    def test_each_variant_and_negative_controls(self):
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            for port, probes in PROBES.items():
                for index, probe in enumerate(probes):
                    with self.subTest(host=host, port=port, variant=index):
                        self.fixture(family, host, port, probe, "same-peer")
                for response in ["silent", "other-peer"]:
                    with self.subTest(host=host, port=port, response=response):
                        self.fixture(family, host, port, probes[-1], response)
                with self.subTest(host=host, port=port, response="closed"):
                    self.assertFalse(scan(port, host))


if __name__ == "__main__":
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    unittest.main()
