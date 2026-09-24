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

#[test]
fn udp_detects_a_response_to_each_variant_including_empty_replies() {
    block_on(async {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            for accepted in 0..3 {
                let server = UdpSocket::bind(address).await.unwrap();
                let target = server.local_addr().unwrap();
                let responder = spawn(async move {
                    let mut buf = [0; 16];
                    let mut peers = Vec::new();
                    for expected in 0..=accepted {
                        let (size, peer) =
                            io::timeout(Duration::from_secs(3), server.recv_from(&mut buf))
                                .await
                                .unwrap();
                        assert_eq!(
                            &buf[..size],
                            [b"first".as_slice(), b"second", b"third"][expected]
                        );
                        peers.push(peer);
                    }
                    server.send_to(&[], peers[0]).await.unwrap();
                    let extra =
                        io::timeout(Duration::from_millis(350), server.recv_from(&mut buf)).await;
                    assert!(extra.is_err(), "must stop sending after confirmation");
                    assert!(peers.iter().all(|peer| *peer == peers[0]));
                });
                assert!(scanner(Duration::from_millis(600), 1)
                    .udp_scan(target, &[b"first", b"second", b"third"])
                    .await
                    .unwrap());
                responder.await;
            }
        }
    });
}

#[test]
fn udp_accepts_late_replies_across_variants_and_attempts() {
    block_on(async {
        for (variants, tries) in [(true, 1), (false, 2)] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = server.local_addr().unwrap();
            let responder = spawn(async move {
                let mut buf = [0; 16];
                let (_, first) = server.recv_from(&mut buf).await.unwrap();
                sleep(Duration::from_millis(300)).await;
                server.send_to(b"late", first).await.unwrap();
                let (_, next) = server.recv_from(&mut buf).await.unwrap();
                assert_eq!(first, next, "variants/retries must retain the source port");
            });
            let (timeout, payloads): (_, &[&[u8]]) = if variants {
                (Duration::from_millis(600), &[b"first", b"second", b"third"])
            } else {
                (Duration::from_millis(200), &[b"first"])
            };
            assert!(scanner(timeout, tries)
                .udp_scan(target, payloads)
                .await
                .unwrap());
            responder.await;
        }
    });
}

#[test]
fn udp_silent_ports_have_a_fixed_time_and_packet_budget() {
    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let start = Instant::now();
        let payloads: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e"];
        assert!(!scanner(Duration::from_millis(200), 2)
            .udp_scan(target, payloads)
            .await
            .unwrap());
        // A timeout per payload would take two seconds, instead of ~400 ms.
        assert!(start.elapsed() < Duration::from_millis(1200));
        let mut packets = Vec::new();
        let mut buf = [0; 16];
        while let Ok((size, peer)) =
            io::timeout(Duration::from_millis(20), server.recv_from(&mut buf)).await
        {
            packets.push((buf[..size].to_vec(), peer));
        }
        assert_eq!(packets.len(), 10);
        for (index, (payload, peer)) in packets.iter().enumerate() {
            assert_eq!(payload, payloads[index % payloads.len()]);
            assert_eq!(*peer, packets[0].1);
        }
    });
}

#[test]
fn udp_empty_probe_fallback_still_detects_a_listener() {
    block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let responder = spawn(async move {
            let mut buf = [0; 16];
            let (size, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(size, 0);
            server.send_to(b"response", peer).await.unwrap();
        });
        assert!(scanner(Duration::from_secs(1), 1)
            .udp_scan(target, &[&[]])
            .await
            .unwrap());
        responder.await;
    });
}
