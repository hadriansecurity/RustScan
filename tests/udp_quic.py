"""Discovery against aioquic's actual server, without completing a handshake.

pip install -r tests/udp-requirements.txt
sudo unshare --net /path/to/venv/bin/python tests/udp_quic.py target/debug/rustscan
Optional second binary: compare the prerequisite Nmap-only build as well.
"""
import asyncio
import pathlib
import socket
import subprocess
import sys
import unittest

from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
BASELINE = str(pathlib.Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else None


class QuicDiscovery(unittest.IsolatedAsyncioTestCase):
    async def scan(self, binary, host):
        process = await asyncio.create_subprocess_exec(
            binary, "--no-config", "--addresses", host, "--ports", "443",
            "--udp", "--greppable", "--timeout", "300", "--tries", "1",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=5)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        self.assertEqual(process.returncode, 0, err.decode())
        return f"{host} -> [443]" in out.decode()

    async def test_real_server_requires_modern_probe(self):
        loop = asyncio.get_running_loop()
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            with self.subTest(host=host):
                # QuicServer itself parses packets and sends Version Negotiation.
                # No mock response and no certificate needed before a handshake.
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: QuicServer(configuration=QuicConfiguration(is_client=False)),
                    local_addr=(host, 443), family=family,
                )
                try:
                    # The empty fallback and both legacy Q999 probes get silence.
                    for probe in [b"", b"\r12345678Q999\0",
                                  bytes.fromhex("0d89c19c1c2afffcf15139393900")]:
                        with socket.socket(family, socket.SOCK_DGRAM) as client:
                            client.setblocking(False)
                            await loop.sock_sendto(client, probe, (host, 443))
                            with self.assertRaises(asyncio.TimeoutError):
                                await asyncio.wait_for(loop.sock_recvfrom(client, 4096), 0.1)
                    if BASELINE:
                        self.assertFalse(await self.scan(BASELINE, host))
                    self.assertTrue(await self.scan(BINARY, host))
                finally:
                    transport.close()
                    await asyncio.sleep(0)


if __name__ == "__main__":
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    unittest.main()
