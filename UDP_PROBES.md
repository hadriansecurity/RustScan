# UDP discovery probes

The build reads the vendored `nmap-payloads` file. It preserves inline-commented
payloads, inclusive port ranges, entries with identical or overlapping port
lists, and the final entry at EOF. Exact duplicate payload bytes on a port are
sent only once. Malformed entries fail the build with a source line number.
Optional metadata after the quoted payload remains ignored, including `source`.

Generated code lives in Cargo's `OUT_DIR`, not the source tree. Payload bytes are
static and shared. A lazily initialized per-port index is used only by UDP scans;
TCP scans no longer initialize or clone the UDP table. The internal public
`generated::get_parsed_data` API now returns a map from port to a vector of static
payload slices rather than a map from port lists to one owned payload.

## Scheduling and performance

- A port's distinct probes are sent in database order. A port without a registered
  probe receives one empty datagram, as before.
- Each attempt shares the existing `--timeout` budget across its probes. Probes
  are spaced evenly within that window while the socket waits for a response.
  For example, two probes with `--timeout 500` are scheduled at approximately
  0 and 250 ms, with the attempt ending at 500 ms.
- Any response, including an empty datagram, confirms the port and stops further
  probes. The same connected socket is retained across variants and `--tries`,
  allowing responses to earlier probes to arrive during subsequent waits.
- A silent port sends at most `distinct probes × tries` packets. Its probe/receive
  time budget remains `timeout × tries`, rather than multiplying by the probe
  count. Socket setup and scheduler overhead are additional. Under severe load,
  a deadline can expire before all scheduled variants are sent.
- With the current database, 20 ports have multiple probes, with at most four
  variants per port. One attempt over ports 1-65535 has a maximum of 65,559
  datagrams versus 65,535 previously: 24 extra packets if nothing responds. A
  selected subset containing those ports can have a larger proportional increase.
  Restoring missing payloads can also increase bytes per packet.

This policy avoids a full additional timeout for every variant. Its tradeoff is
that later variants have a shorter response window: it is not equivalent to
Nmap's adaptive retransmission/timing or service detection. `--batch-size` bounds
concurrent target sockets; it is not a global packets-per-second limit. This
change does not update the probe database, increase default retries/timeouts, or
modify the consuming port-scanner module.

## Regression checks

`cargo test --test udp_database --test udp_payloads` checks parsing, exact probe
bytes, variant preservation, generated coverage counts, and shared storage.
`cargo test --lib scanner::udp_tests` uses local IPv4/IPv6 UDP fixtures to check
responses to each variant, empty replies, early stopping, delayed replies across
variants/retries, and the time/packet budget for silent ports.
