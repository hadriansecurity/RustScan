use super::*;
use crate::input::ScanOrder;
use async_std::task::{block_on, sleep, spawn};

fn scanner(timeout: Duration, tries: u8) -> Scanner {
    Scanner::new(
        &[],
        1,
        timeout,
        tries,
        true,
        PortStrategy::pick(Some(vec![53]), ScanOrder::Serial),
        true,
        vec![],
        true,
    )
}

async fn receive(server: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0; 64];
    let (size, peer) = io::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .unwrap();
    (buf[..size].to_vec(), peer)
}

#[test]
fn udp_detects_a_response_to_each_variant_including_empty_replies() {
    block_on(async {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            for accepted in 0..4 {
                let server = UdpSocket::bind(address).await.unwrap();
                let target = server.local_addr().unwrap();
                let payloads: &[&[u8]] = &[b"first", b"second", b"third", b"fourth"];
                let responder = spawn(async move {
                    let mut peers = Vec::new();
                    for (index, expected) in payloads.iter().enumerate() {
                        let (payload, peer) = receive(&server).await;
                        assert_eq!(payload, *expected);
                        peers.push(peer);
                        if index == accepted {
                            server.send_to(&[], peer).await.unwrap();
                        }
                    }
                    assert!(peers.iter().all(|peer| *peer == peers[0]));
                });
                assert!(scanner(Duration::from_secs(2), 2)
                    .udp_scan(target, payloads)
                    .await
                    .unwrap());
                responder.await;
            }
        }
    });
}

#[test]
fn udp_last_variant_has_the_response_window_without_staggering() {
    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let responder = spawn(async move {
            for expected in [b"first".as_slice(), b"second", b"third"] {
                assert_eq!(receive(&server).await.0, expected);
            }
            let (payload, peer) = receive(&server).await;
            assert_eq!(payload, b"fourth");
            // Half the attempt window: a staggered fourth probe would only
            // have one quarter remaining. The one-second margin tolerates CI load.
            sleep(Duration::from_secs(1)).await;
            server.send_to(b"response", peer).await.unwrap();
        });
        assert!(scanner(Duration::from_secs(2), 1)
            .udp_scan(target, &[b"first", b"second", b"third", b"fourth"])
            .await
            .unwrap());
        responder.await;
    });
}

#[test]
fn udp_accepts_a_reply_to_the_first_attempt_after_the_retry_arrives() {
    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let responder = spawn(async move {
            let (payload, first) = receive(&server).await;
            assert_eq!(payload, b"probe");
            // The retry packet is the synchronization point; no sleep guesses
            // when the first attempt has expired.
            let (payload, next) = receive(&server).await;
            assert_eq!(payload, b"probe");
            assert_eq!(first, next, "retries must retain the source port");
            server.send_to(b"late", first).await.unwrap();
        });
        assert!(scanner(Duration::from_secs(1), 2)
            .udp_scan(target, &[b"probe"])
            .await
            .unwrap());
        responder.await;
    });
}

#[test]
fn udp_silent_ports_have_a_fixed_time_and_packet_budget() {
    block_on(async {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = server.local_addr().unwrap();
        let payloads: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"];
        // Normal completion is ~500 ms. A timeout per payload would take four
        // seconds; the outer test bound allows substantial scheduling slack.
        let found = io::timeout(
            Duration::from_secs(2),
            scanner(Duration::from_millis(250), 2).udp_scan(target, payloads),
        )
        .await
        .unwrap();
        assert!(!found);
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
fn udp_empty_probe_fallback_and_explicit_empty_payload_detect_a_listener() {
    block_on(async {
        for payloads in [&[][..], &[&[][..]][..]] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = server.local_addr().unwrap();
            let responder = spawn(async move {
                let (payload, peer) = receive(&server).await;
                assert!(payload.is_empty());
                server.send_to(b"response", peer).await.unwrap();
            });
            assert!(scanner(Duration::from_secs(2), 1)
                .udp_scan(target, payloads)
                .await
                .unwrap());
            responder.await;
        }
    });
}
