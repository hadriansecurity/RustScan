"""Linux regression tests using real ICMP errors, in a private network namespace.

Run: sudo unshare --net python3 tests/udp_rejection.py target/debug/rustscan
Requires iproute2 and iptables. No firewall rules touch the host namespace.
"""

import pathlib
import socket
import subprocess
import sys
import threading
import time
import unittest


BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
DNS_STATUS = bytes.fromhex("000010000000000000000000")


class UdpRejection(unittest.TestCase):
    def setUp(self):
        self.rules = []
        self.server = None
        self.thread = None
        self.stop = threading.Event()
        self.packets = []

    def tearDown(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.server:
            self.server.close()
        for rule in reversed(self.rules):
            subprocess.run(["iptables", "-D", "INPUT", *rule], check=True)

    def reject(self, length=None):
        rule = ["-p", "udp", "--dport", "53"]
        if length is not None:
            rule += ["-m", "length", "--length", str(length)]
        rule += ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"]
        subprocess.run(["iptables", "-A", "INPUT", *rule], check=True)
        self.rules.append(rule)

    def listen(self, respond=True, reply_after=1):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 53))
        self.server.settimeout(0.05)

        def serve():
            while not self.stop.is_set():
                try:
                    payload, peer = self.server.recvfrom(4096)
                except socket.timeout:
                    continue
                self.packets.append((payload, peer))
                if respond and len(self.packets) >= reply_after:
                    self.server.sendto(b"reply", peer)

        self.thread = threading.Thread(target=serve)
        self.thread.start()

    def scan(self, port=53, timeout=150, tries=2):
        started = time.monotonic()
        result = subprocess.run(
            [BINARY, "--no-config", "--addresses", "127.0.0.1", "--ports", str(port),
             "--udp", "--greppable", "--timeout", str(timeout), "--tries", str(tries)],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return f"127.0.0.1 -> [{port}]" in result.stdout, time.monotonic() - started

    def test_rejected_first_variant_does_not_prevent_second_send(self):
        self.listen()
        self.reject(length=28 + len(DNS_STATUS))
        found, _ = self.scan()
        self.assertTrue(found, "ICMP for DNS Status must not prevent DNS Version")
        self.assertTrue(any(b"version" in payload for payload, _ in self.packets))

    def test_rejected_second_variant_does_not_hide_first_reply(self):
        self.listen()
        self.reject(length=28 + 30)  # IPv4 + UDP headers + DNS Version payload
        found, _ = self.scan()
        self.assertTrue(found, "ICMP for DNS Version must not hide the DNS Status reply")
        self.assertTrue(any(payload == DNS_STATUS for payload, _ in self.packets))

    def test_rejection_recovery_also_works_during_retry(self):
        self.listen(reply_after=2)
        self.reject(length=28 + len(DNS_STATUS))
        found, _ = self.scan()
        self.assertTrue(found, "the retry must also send DNS Version after a rejection")
        self.assertEqual(len(self.packets), 2)
        self.assertEqual(len({peer for _, peer in self.packets}), 1)

    def test_all_variants_rejected_remain_closed_and_bounded(self):
        self.listen()
        self.reject()
        found, elapsed = self.scan()
        self.assertFalse(found)
        self.assertLess(elapsed, 2)
        self.assertEqual(self.packets, [])

    def test_closed_multi_probe_port_is_not_reported(self):
        found, elapsed = self.scan()
        self.assertFalse(found)
        self.assertLess(elapsed, 2)

    def test_single_probe_closed_port_still_fails_promptly(self):
        found, elapsed = self.scan(port=7, timeout=3000)
        self.assertFalse(found)
        self.assertLess(elapsed, 2)

    def test_silent_multi_probe_port_keeps_its_packet_budget(self):
        self.listen(respond=False)
        found, elapsed = self.scan()
        self.assertFalse(found)
        self.assertLess(elapsed, 2)
        self.assertEqual(len(self.packets), 4)
        self.assertEqual(len({peer for _, peer in self.packets}), 1)


if __name__ == "__main__":
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    unittest.main()
