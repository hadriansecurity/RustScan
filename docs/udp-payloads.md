# UDP discovery payloads

RustScan generates its UDP discovery table solely from the pinned
`nmap-service-probes` at build time. It preserves eligible probe order and
removes byte-identical duplicates per port. Payload bytes are shared in the
compiled table; no Nmap installation or database download is required at build
or scan time.

## Pinned source and selection

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
The `no-payload` prefix check deliberately matches Nmap's ten-byte `strncmp`.

This pin has 83 eligible definitions, covering 33,110 ports and 33,204 distinct
(port, payload) pairs; 86 ports have multiple variants. This is payload-selection
parity with the pinned Nmap, not parity with its timing or `-sV` service
identification.

The old `nmap-payloads` snapshot and its parser have been removed. Its 47
legacy-only pairs were mostly older or different requests on ports already
covered by Nmap, rather than demonstrated additional coverage. UDP/4500 is the
only destination that loses a specific probe and now receives an empty datagram,
as it does with this Nmap pin. No local exception is retained. SQL Browser's
`no-payload` exclusion is also preserved.

## Packet budget

For a target port, an attempt sends each distinct variant once, or one empty
UDP datagram when no variant exists. There is one timeout per attempt, and the
socket stays alive across retries. Successful replies or explicit rejection
can end the scan early.

For ports **1–65535**, per target IP:

| Measure | Legacy-only prerequisite | Current Nmap table |
| --- | ---: | ---: |
| Ports with a specific probe | 33,053 | 33,110 |
| Distinct (port, payload) pairs | 33,077 | 33,204 |
| Maximum variants on one port | 4 | 4 |
| Maximum datagrams, `--tries 1` (default) | 65,559 | **65,629** |
| Maximum datagrams, `--tries 2` | 131,118 | **131,258** |

The bound is `65,535 - 33,110 + 33,204 = 65,629` datagrams per attempt,
70 more than the legacy-only prerequisite. Removing the initially retained
legacy variants reduces the former merged bound of 65,675 by 46: removing the
4500 probe substitutes an empty datagram rather than removing a datagram.
For `--tries N`, multiply by `max(N, 1)`; the CLI treats zero tries as one.
These are transmitted UDP datagrams, excluding IP/UDP headers, ICMP responses,
and any separate Nmap follow-up. Explicitly including port 0 adds one empty
datagram per attempt. These bounds are asserted in `tests/udp_payloads.rs`.

## Independent Nmap reference

`fixtures/nmap-udp-selection.tsv` records the actual pinned Nmap payload
API's output, compressed by grouping identical payload bytes across port ranges.
Its SHA-256 is `71545be7f0133d2ba9e1335adf203775b3e4cd1eb9dacb58122d954ee16c16b6`.
The test compares both our parser and the generated lookup directly against
that reference for **every port 0–65535**. Separate tests enforce uniqueness
and source ordering.

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

## Network validation

The committed `tests/udp_service_probes.py` checks exact probe bytes and
discovery on **523 (DB2 DAS), 3483 (SqueezeCenter), and 5060 (SIP OPTIONS)** over
IPv4 and IPv6, with silent, closed, and alternate-source-port controls (24
scenarios). The six ignored Rust UDP socket tests in
`src/scanner/udp_socket_tests.rs` cover replies, retries, silent-port budgets,
empty probes, closed ports, and the response window for the last variant.
The Python ICMP rejection harness remains removed, as on the prerequisite branch.

Run these on Linux (requires Python, iproute2, and permission to
create a network namespace):

```sh
cargo build --locked
cargo test --locked --lib udp_socket_tests -- --ignored
sudo unshare --net python3 tests/udp_service_probes.py target/debug/rustscan
```

The service-probe script is run manually using the commands above. The Rust
UDP socket tests run in the manually dispatched UDP regression workflow.
These controlled results and payload parity do
not establish detection rates on arbitrary services. The earlier 115-port
full-range testbed result applied to the table that still retained legacy
variants; it is not evidence that removing those variants preserves every
legacy service response.

On 2026-10-07, the build rebased onto the compile-time lookup in PR #11 passed
all 24 service-probe scenarios and all six Rust UDP socket tests in an isolated
Linux container. Rust validation passed: 95 unit/integration tests, seven
doctests (one ignored), Clippy across all targets with warnings denied,
formatting, and the documentation build.
