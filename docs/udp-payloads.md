# UDP discovery payloads

RustScan merges the existing `nmap-payloads` with the vendored
`nmap-service-probes` at build time. It keeps legacy variants first, appends
eligible service probes in file order, and removes byte-identical duplicates
per port. Payload bytes are shared in the compiled table; no Nmap installation
or database download is required at build or scan time.

## Pinned source

- Nmap version: **7.991SVN** (`nmap.h` at the revision below).
- Commit: **24229f2e65aa11ca860b5c4ec6b4757dc2d8afd0**.
- Database: [upstream nmap-service-probes](https://github.com/nmap/nmap/blob/24229f2e65aa11ca860b5c4ec6b4757dc2d8afd0/nmap-service-probes), vendored without modifications.
- SHA-256: `bd1bc6b1904632c617d6cf70e1f21877f4b0abefc8db977ceaf1699accdde5ff`.
- License: the database retains its copyright notice; the corresponding upstream
  license is included as [`LICENSE.nmap`](../LICENSE.nmap).

The selection follows Nmap's [`init_payloads`](https://github.com/nmap/nmap/blob/24229f2e65aa11ca860b5c4ec6b4757dc2d8afd0/payload.cc):
only `Probe UDP` records without `no-payload` contribute, and only their `ports`
lists supply destinations. Ranges include both endpoints. `sslports`, `Exclude`,
rarity, and service match rules do not affect discovery-payload selection.
Probe strings use Nmap's delimiters and strict `cstring_unescape` rules.
TCP probes and UDP probes without destination ports contribute nothing.

This pin has 83 eligible definitions, covering 33,110 ports and 33,204 distinct
(port, payload) pairs. The merged RustScan table covers 33,111 ports and 33,251
pairs; 124 ports have multiple variants. The extra pairs preserve legacy probes.
This is payload-selection parity, not parity with Nmap's timing or `-sV` service
identification.

## Packet budget

For a target port, an attempt sends each distinct variant once, or one empty
UDP datagram when no variant exists. There is one timeout per attempt, and the
socket stays alive across retries. Successful replies or explicit rejection
can end the scan early.

For ports **1–65535**, per target IP:

| Measure | Legacy-only prerequisite | Merged table |
| --- | ---: | ---: |
| Ports with a specific probe | 33,053 | 33,111 |
| Distinct (port, payload) pairs | 33,077 | 33,251 |
| Maximum variants on one port | 4 | 5 |
| Maximum datagrams, `--tries 1` (default) | 65,559 | **65,675** |
| Maximum datagrams, `--tries 2` | 131,118 | **131,350** |

The merged bound is `65,535 - 33,111 + 33,251 = 65,675` datagrams per attempt,
an increase of 116 (about 0.18%). For `--tries N`, multiply by `max(N, 1)`;
the CLI treats zero tries as one. These are transmitted UDP datagrams, excluding
IP/UDP headers, ICMP responses, and any separate Nmap follow-up. Port 0 is
excluded from the ordinary full range; explicitly including it adds one empty
datagram per attempt. These bounds are asserted in `tests/udp_payloads.rs`.

## Independent Nmap reference

`fixtures/nmap-udp-selection.tsv` records the actual pinned Nmap payload
API's output, compressed by grouping identical payload bytes across port ranges.
Its SHA-256 is `71545be7f0133d2ba9e1335adf203775b3e4cd1eb9dacb58122d954ee16c16b6`.
The test compares our service-probe parser against that reference for **every
port 0–65535**, then compares the generated lookup against the union of the
reference and the legacy probes. Separate tests enforce uniqueness and ordering.

To regenerate, extract the [pinned Nmap source archive](https://github.com/nmap/nmap/archive/24229f2e65aa11ca860b5c4ec6b4757dc2d8afd0.tar.gz), then run:

```sh
python3 tests/nmap_reference.py /path/to/extracted/nmap-source
cargo test --locked --test udp_payloads
```

The helper verifies the pinned source hashes, builds a temporary source copy,
and inserts an early export in `nmap_main` that calls Nmap's `init_payloads`,
`udp_payload_count`, and `get_udp_payload` for every port. It makes no network
probes. It requires a C/C++ build toolchain and make; normal Rust tests use the
committed fixture and need neither Nmap nor that toolchain. When updating the
pin, review the source rules, regenerate the reference and hashes, and update
the version, coverage counts, and packet-budget assertions together.

## Acceptance results (2026-10-06)

The local port-scanner testbed ran in a Docker container with `--network none`.
A full-range loopback scan used:

```sh
rustscan --no-config --addresses 127.0.0.1 --range 1-65535 \
  --udp --greppable --timeout 500 --tries 1 --batch-size 256
```

All **115 expected open ports** were found, including **523 (DB2 DAS),
3483 (SqueezeCenter), and 5060 (SIP OPTIONS)**. No ports among the **100 silent,
1,000 filtered, or 64,320 closed controls** were reported open: **zero false
positives and zero false negatives** in this controlled testbed.
The testbed configuration SHA-256 was
`268e3f4eb76546631afc1189f79b4aaf94c081fa784dddc96ccf9544f97e28e0`.

The committed `tests/udp_service_probes.py` additionally checks exact probe
bytes and discovery on those three ports over IPv4 and IPv6, with silent,
closed, and alternate-source-port controls (24 scenarios). The eight existing
ICMP rejection/packet-budget regressions also pass with the new DNS variants.
These controlled results do not establish detection rates on arbitrary services.

Run the network regressions on Linux (requires Python, iproute2, iptables, and
permission to create a network namespace):

```sh
cargo build --locked
sudo unshare --net python3 tests/udp_rejection.py target/debug/rustscan
sudo unshare --net python3 tests/udp_service_probes.py target/debug/rustscan
```

Both scripts run in Linux CI. Rust validation also passed: 99 unit/integration
tests, seven doctests (one existing ignored), Clippy across all targets with
warnings denied, formatting, and the documentation build.
