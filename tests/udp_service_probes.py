"""Loopback acceptance tests for service-probe discovery and negative controls.

Run: sudo unshare --net python3 tests/udp_service_probes.py target/debug/rustscan
Linux requires iproute2. The fixtures bind only loopback, including UDP/523.
"""
import pathlib
import socket
import subprocess
import sys
import threading
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
PROBES = {
    523: b"DB2GETADDR\0SQL08010\0",
    3483: b"eIPAD\0NAME\0JSON\0VERS\0UUID\0JVID\x06\x12\x34\x56\x78\x12\x34",
    5060: (b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo;rport\r\n"
           b"From: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\n"
           b"CSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n"
           b"Contact: <sip:nm@nm>\r\nAccept: application/sdp\r\n\r\n"),
}


class ServiceProbes(unittest.TestCase):
    def scan(self, port, host):
        result = subprocess.run(
            [BINARY, "--no-config", "--addresses", host, "--ports", str(port),
             "--udp", "--greppable", "--timeout", "200", "--tries", "2"],
            text=True, capture_output=True, check=True, timeout=5,
        )
        return f"{host} -> [{port}]" in result.stdout

    def fixture(self, family, host, port, response):
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
                    if payload != PROBES[port]:
                        continue
                    if response == "same-peer":
                        server.sendto(b"reply", peer)
                    elif response == "other-peer":
                        alternate.sendto(b"reply", peer)

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                found = self.scan(port, host)
            finally:
                stopped.set()
                worker.join(timeout=2)
            self.assertIn(PROBES[port], received)
            self.assertNotIn(b"", received)
            self.assertEqual(found, response == "same-peer")
            if response != "same-peer":
                self.assertEqual(received, [PROBES[port]] * 2)

    def test_services_and_negative_controls(self):
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            for port in PROBES:
                for response in ["same-peer", "silent", "other-peer"]:
                    with self.subTest(host=host, port=port, response=response):
                        self.fixture(family, host, port, response)
                with self.subTest(host=host, port=port, response="closed"):
                    self.assertFalse(self.scan(port, host))


if __name__ == "__main__":
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    unittest.main()
