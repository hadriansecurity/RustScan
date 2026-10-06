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
        self.packet_received = threading.Event()

    def tearDown(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.server:
            self.server.close()
        for rule in reversed(self.rules):
            subprocess.run(["iptables", "-D", "INPUT", *rule], check=True)

    def reject(self, length=None, reject_with="icmp-port-unreachable"):
        rule = ["-p", "udp", "--dport", "53"]
        if length is not None:
            rule += ["-m", "length", "--length", str(length)]
        rule += ["-j", "REJECT", "--reject-with", reject_with]
        subprocess.run(["iptables", "-A", "INPUT", *rule], check=True)
        self.rules.append(rule)

    def listen(self, respond=True, close_after=None):
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
                self.packet_received.set()
                if close_after and len(self.packets) >= close_after:
                    self.server.close()
                    return
                if respond:
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
        self.listen(respond=False)
        self.reject(length=28 + len(DNS_STATUS))
        found, elapsed = self.scan(timeout=3000)
        self.assertFalse(found)
        self.assertLess(elapsed, 2, "a send-side rejection must not wait for a reply")
        self.assertTrue(self.packet_received.wait(1))
        self.assertTrue(any(b"version" in payload for payload, _ in self.packets))
        self.assertEqual(len(self.packets), 1, "rejection must not trigger another attempt")

    def test_rejected_second_variant_stops_without_waiting_for_first_reply(self):
        self.listen(respond=False)
        self.reject(length=28 + 30)  # IPv4 + UDP headers + DNS Version payload
        found, elapsed = self.scan(timeout=3000)
        self.assertFalse(found)
        self.assertLess(elapsed, 2, "a receive-side rejection must finish promptly")
        self.assertTrue(self.packet_received.wait(1))
        self.assertEqual([payload for payload, _ in self.packets], [DNS_STATUS])

    def test_rejection_during_retry_stops_remaining_attempts(self):
        # The first burst is silently accepted; closing the socket causes the
        # next attempt to receive real ICMP errors through the async path.
        self.listen(respond=False, close_after=2)
        found, elapsed = self.scan(timeout=150, tries=20)
        self.assertFalse(found)
        self.assertLess(elapsed, 2, "rejection must not consume all 20 timeouts")
        self.assertEqual(len(self.packets), 2)

    def test_all_variants_rejected_finish_promptly(self):
        self.listen()
        self.reject()
        found, elapsed = self.scan(timeout=3000)
        self.assertFalse(found)
        self.assertLess(elapsed, 2)
        self.assertEqual(self.packets, [])

    def test_explicit_filter_rejection_finishes_promptly(self):
        self.listen()
        self.reject(reject_with="icmp-admin-prohibited")
        found, elapsed = self.scan(timeout=3000)
        self.assertFalse(found)
        self.assertLess(elapsed, 2)
        self.assertEqual(self.packets, [])

    def test_closed_multi_probe_port_finishes_promptly(self):
        found, elapsed = self.scan(timeout=3000)
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
