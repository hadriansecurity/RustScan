//! UDP scans against loopback listeners. They open sockets, so they are
//! ignored by default and run by the "UDP regression" workflow:
//! `cargo test --lib udp_socket_tests -- --ignored`.

use super::*;
use crate::input::ScanOrder;
use std::future::Future;
use tokio::task::spawn;

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(future)
}

fn udp_scanner(timeout: Duration, tries: u8) -> Scanner {
    Scanner::new(
        &[],
        1,
        timeout,
        tries,
        true,
        PortStrategy::pick(&None, Some(vec![53]), ScanOrder::Serial),
        true,
        vec![],
        true,
    )
}

async fn scan(
    scanner: &Scanner,
    target: SocketAddr,
    payloads: &[&'static [u8]],
) -> io::Result<PortStatus> {
    scanner.scan_udp_socket(target, payloads).await
}

async fn receive(server: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0; 64];
    let (size, peer) = timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    (buf[..size].to_vec(), peer)
}

#[test]
#[ignore = "opens sockets; run by the UDP regression workflow"]
fn a_reply_to_any_variant_marks_the_port_open() {
    block_on(async {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            for answered in 0..4 {
                let server = UdpSocket::bind(address).await.unwrap();
                let target = server.local_addr().unwrap();
                let payloads: &[&[u8]] = &[b"first", b"second", b"third", b"fourth"];
                let responder = spawn(async move {
                    let mut peers = Vec::new();
                    for (index, expected) in payloads.iter().enumerate() {
                        let (payload, peer) = receive(&server).await;
                        assert_eq!(payload, *expected);
                        peers.push(peer);
                        if index == answered {
                            server.send_to(&[], peer).await.unwrap();
                        }
                    }
                    assert!(peers.iter().all(|peer| *peer == peers[0]));
                });
                let status = scan(&udp_scanner(Duration::from_secs(2), 2), target, payloads).await;
                assert!(matches!(status, Ok(PortStatus::Open(_))), "{:?}", status);
                responder.await.unwrap();
            }
        }
    });
}

#[test]
#[ignore = "opens sockets; run by the UDP regression workflow"]
fn the_last_variant_gets_the_whole_response_window() {
    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let responder = spawn(async move {
            for expected in [b"first".as_slice(), b"second", b"third"] {
                assert_eq!(receive(&server).await.0, expected);
            }
            let (payload, peer) = receive(&server).await;
            assert_eq!(payload, b"fourth");
            // Half the attempt window: if each variant got its own slice of
            // the timeout, the fourth would have only a quarter left.
            sleep(Duration::from_secs(1)).await;
            server.send_to(b"response", peer).await.unwrap();
        });
        let payloads: &[&[u8]] = &[b"first", b"second", b"third", b"fourth"];
        let status = scan(&udp_scanner(Duration::from_secs(2), 1), target, payloads).await;
        assert!(matches!(status, Ok(PortStatus::Open(_))), "{:?}", status);
        responder.await.unwrap();
    });
}

#[test]
#[ignore = "opens sockets; run by the UDP regression workflow"]
fn a_late_reply_to_the_first_attempt_still_counts() {
    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let responder = spawn(async move {
            let (payload, first) = receive(&server).await;
            assert_eq!(payload, b"probe");
            // The retry is the signal that the first attempt has expired.
            let (payload, retry) = receive(&server).await;
            assert_eq!(payload, b"probe");
            assert_eq!(first, retry, "retries must keep the source port");
            server.send_to(b"late", first).await.unwrap();
        });
        let status = scan(&udp_scanner(Duration::from_secs(1), 2), target, &[b"probe"]).await;
        assert!(matches!(status, Ok(PortStatus::Open(_))), "{:?}", status);
        responder.await.unwrap();
    });
}

#[test]
#[ignore = "opens sockets; run by the UDP regression workflow"]
fn silent_ports_send_each_variant_once_per_attempt() {
    block_on(async {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = server.local_addr().unwrap();
        let payloads: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"];
        // Two attempts of 250 ms take about 500 ms; a timeout per variant
        // would take four seconds.
        let status = timeout(
            Duration::from_secs(2),
            scan(
                &udp_scanner(Duration::from_millis(250), 2),
                target,
                payloads,
            ),
        )
        .await
        .expect("silent port scan overran its time budget");
        assert_eq!(status.unwrap_err().kind(), io::ErrorKind::Other);

        server.set_nonblocking(true).unwrap();
        let mut packets = Vec::new();
        let mut buf = [0; 16];
        loop {
            match server.recv_from(&mut buf) {
                Ok((size, peer)) => packets.push((buf[..size].to_vec(), peer)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("receive failed: {}", e),
            }
        }
        assert_eq!(packets.len(), payloads.len() * 2);
        for (index, (payload, peer)) in packets.iter().enumerate() {
            assert_eq!(payload, payloads[index % payloads.len()]);
            assert_eq!(*peer, packets[0].1);
        }
    });
}

#[test]
#[ignore = "opens sockets; run by the UDP regression workflow"]
fn ports_without_a_payload_get_one_empty_datagram() {
    block_on(async {
        for payloads in [&[][..], &[&[][..]][..]] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = server.local_addr().unwrap();
            let responder = spawn(async move {
                let (payload, peer) = receive(&server).await;
                assert!(payload.is_empty());
                server.send_to(b"response", peer).await.unwrap();
            });
            let status = scan(&udp_scanner(Duration::from_secs(2), 1), target, payloads).await;
            assert!(matches!(status, Ok(PortStatus::Open(_))), "{:?}", status);
            responder.await.unwrap();
        }
    });
}

#[test]
#[ignore = "opens sockets; run by the UDP regression workflow"]
fn a_closed_port_fails_without_waiting_for_the_timeout() {
    block_on(async {
        let single: &[&[u8]] = &[b"probe"];
        let multiple: &[&[u8]] = &[b"first", b"second"];
        for payloads in [single, multiple] {
            let target = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let status = timeout(
                Duration::from_secs(2),
                scan(&udp_scanner(Duration::from_secs(3), 20), target, payloads),
            )
            .await
            .expect("rejection did not end the scan");
            assert_eq!(status.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        }
    });
}
