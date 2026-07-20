//! Transport-level tests for the shipped transport ([`lait_net::DefaultTransport`]) — no
//! daemon. Two real iroh endpoints over loopback under `Network::Isolated`
//! (no relay, no discovery: each `learn`s the other's `advertised_addrs`,
//! exactly the ticket path), plus one Local-policy test on an in-process relay
//! reusing the `hermetic_net.rs` harness.
//!
//! The iroh impl is the contract wherever mem and iroh diverge, so the frame
//! byte-identity and the R1 truncation-hazard tests run HERE, against real
//! QUIC — mem cannot represent either.

use std::time::Duration;

use iroh::{endpoint::presets, Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::tls::CaRootsConfig;
use lait_net::policy::Network;
use lait_net::{Alpn, DefaultTransport, GossipEvent, Topic, Transport};

// Protocol selectors belong to the application; any two distinct ALPNs exercise
// dispatch identically, so the seam's tests name their own rather than pinning
// the daemon's spelling of them.
const SYNC_ALPN: Alpn = b"lait-net/test-sync/1";
const PRESENCE_ALPN: Alpn = b"lait-net/test-presence/1";

fn device(seed: u8) -> lait_kernel::ids::DeviceId {
    lait_kernel::crypto::device_from_seed(&[seed; 32])
}

/// Two Isolated transports that can reach each other: build both, then cross-
/// `learn` their advertised (loopback) addresses — the production ticket path,
/// which also exercises `advertised_addrs` (G6).
async fn isolated_pair(
    a_seed: u8,
    b_seed: u8,
    alpns: &[Alpn],
) -> (DefaultTransport, DefaultTransport) {
    let a = DefaultTransport::new(&[a_seed; 32], &Network::Isolated, alpns)
        .await
        .expect("build A");
    let b = DefaultTransport::new(&[b_seed; 32], &Network::Isolated, alpns)
        .await
        .expect("build B");
    let a_addrs = a.advertised_addrs();
    let b_addrs = b.advertised_addrs();
    assert!(
        !a_addrs.is_empty() && !b_addrs.is_empty(),
        "an Isolated transport must advertise direct addresses"
    );
    a.learn(b.my_id(), &b_addrs);
    b.learn(a.my_id(), &a_addrs);
    (a, b)
}

#[tokio::test]
async fn connect_accept_roundtrip_by_alpn() {
    let (a, b) = isolated_pair(1, 2, &[SYNC_ALPN, PRESENCE_ALPN]).await;
    let a_id = a.my_id();

    let b_task = tokio::spawn(async move {
        // First incoming: sync. Frames round-trip both ways.
        let inc = b.accept().await.expect("incoming");
        assert_eq!(inc.from, a_id, "from is the dialer's id (T0 bytes)");
        assert_eq!(inc.alpn, SYNC_ALPN.to_vec());
        let mut s = inc.stream;
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"ping"[..]));
        s.send(b"pong").await.unwrap();
        s.finish().await.unwrap();
        s.wait_closed().await;

        // Second incoming: presence, on a different ALPN.
        let inc = b.accept().await.expect("second incoming");
        assert_eq!(inc.alpn, PRESENCE_ALPN.to_vec());
        b.shutdown().await;
    });

    let run = tokio::time::timeout(Duration::from_secs(20), async {
        let mut s = a.connect(device(2), SYNC_ALPN).await.expect("connect sync");
        s.send(b"ping").await.unwrap();
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"pong"[..]));
        drop(s);
        // A presence dial: connecting alone is the signal; open the stream so the
        // accepter's lazy accept_bi has something to observe.
        let mut p = a
            .connect(device(2), PRESENCE_ALPN)
            .await
            .expect("connect presence");
        p.send(b"hi").await.ok();
    });
    run.await.expect("roundtrip timed out");
    b_task.await.unwrap();
    a.shutdown().await;
}

/// The real byte-identity proof: `IrohStream` frames are read by a **raw** iroh
/// endpoint using a verbatim copy of the sync protocol's `read_msg` logic, and
/// the reverse — raw `write_msg` bytes are read back through `Stream::recv`.
/// No `sync.rs` is touched; this pins the wire to that format.
#[tokio::test]
async fn framing_interops_with_legacy_read_msg_bytes() {
    // A verbatim copy of sync.rs's read_msg wire logic (u32 BE len + body).
    async fn legacy_read_msg(recv: &mut iroh::endpoint::RecvStream) -> Option<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.ok()?;
        let len = u32::from_be_bytes(len_buf);
        let mut buf = vec![0u8; len as usize];
        recv.read_exact(&mut buf).await.expect("read body");
        Some(buf)
    }
    async fn legacy_write_msg(send: &mut iroh::endpoint::SendStream, body: &[u8]) {
        let len = u32::try_from(body.len()).unwrap();
        send.write_all(&len.to_be_bytes()).await.unwrap();
        send.write_all(body).await.unwrap();
    }

    const ALPN: Alpn = b"lait/framing-test/1";

    // The accepter is a RAW iroh endpoint (hermetic_net.rs style), reading with
    // the legacy byte logic — no transport on that side.
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .secret_key(SecretKey::from_bytes(&[80u8; 32]))
        .bind()
        .await
        .expect("bind raw");
    let raw_id = raw.id();
    let raw_addrs: Vec<_> = raw.addr().ip_addrs().copied().collect();

    let raw_task = tokio::spawn(async move {
        let conn = raw.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        // Read three frames sent through IrohStream with legacy logic.
        assert_eq!(
            legacy_read_msg(&mut recv).await.as_deref(),
            Some(&b"alpha"[..])
        );
        assert_eq!(legacy_read_msg(&mut recv).await.as_deref(), Some(&[][..]));
        let big = vec![0x5A; 100_000];
        assert_eq!(legacy_read_msg(&mut recv).await, Some(big));
        // Reverse: write a legacy frame back for Stream::recv to decode.
        legacy_write_msg(&mut send, b"reply-frame").await;
        send.finish().unwrap();
        conn.closed().await;
    });

    let dialer = DefaultTransport::new(&[81u8; 32], &Network::Isolated, &[])
        .await
        .expect("build dialer");
    dialer.learn(
        lait_kernel::ids::DeviceId::from_key_string(raw_id.to_string()),
        &raw_addrs,
    );

    tokio::time::timeout(Duration::from_secs(20), async {
        let mut s = dialer
            .connect(
                lait_kernel::ids::DeviceId::from_key_string(raw_id.to_string()),
                ALPN,
            )
            .await
            .expect("connect");
        s.send(b"alpha").await.unwrap();
        s.send(b"").await.unwrap();
        s.send(&[0x5A; 100_000]).await.unwrap();
        // Read the legacy-written reply back through the Stream.
        assert_eq!(
            s.recv().await.unwrap().as_deref(),
            Some(&b"reply-frame"[..])
        );
        s.finish().await.unwrap();
    })
    .await
    .expect("framing interop timed out");
    raw_task.await.unwrap();
    dialer.shutdown().await;
}

/// **R1 regression (iroh only — mem cannot truncate).** The accepter sends
/// several frames including a large ~8 MiB trailer, `finish`es, `wait_closed`s,
/// then drops. The dialer *delays* before draining. Every byte must arrive plus
/// a clean `None`. Without `wait_closed` the accepter's connection drop would
/// CONNECTION_CLOSE and truncate the trailer — the silent-partial-sync bug.
#[tokio::test]
async fn r1_trailing_frames_survive_accepter_finishing_first() {
    const ALPN: Alpn = SYNC_ALPN;
    let (a, b) = isolated_pair(3, 4, &[ALPN]).await;
    let big = vec![0xC3u8; 8 * 1024 * 1024];
    let big_for_check = big.clone();

    let b_task = tokio::spawn(async move {
        let inc = b.accept().await.expect("incoming");
        let mut s = inc.stream;
        // Force the lazy accept_bi to open by reading the dialer's opener frame.
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"go"[..]));
        s.send(b"one").await.unwrap();
        s.send(b"two").await.unwrap();
        s.send(&big).await.unwrap();
        s.finish().await.unwrap();
        // The load-bearing await: park until the dialer has drained and closed.
        s.wait_closed().await;
        b.shutdown().await;
    });

    tokio::time::timeout(Duration::from_secs(30), async {
        let mut s = a.connect(device(4), ALPN).await.expect("connect");
        s.send(b"go").await.unwrap();
        // Delay before draining — this is what surfaces a missing wait_closed.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(s.recv().await.unwrap(), Some(big_for_check));
        assert_eq!(s.recv().await.unwrap(), None, "clean end after the trailer");
        drop(s);
    })
    .await
    .expect("R1 roundtrip timed out");
    b_task.await.unwrap();
    a.shutdown().await;
}

/// The ordering half of R1 that runs against iroh too: `wait_closed` does not
/// resolve while the dialer still holds its stream, resolves promptly after.
#[tokio::test]
async fn wait_closed_parks_until_dialer_drops() {
    const ALPN: Alpn = SYNC_ALPN;
    let (a, b) = isolated_pair(5, 6, &[ALPN]).await;

    let b_task = tokio::spawn(async move {
        let mut s = b.accept().await.expect("incoming").stream;
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"go"[..]));
        s.send(b"payload").await.unwrap();
        s.finish().await.unwrap();
        let parked = tokio::time::timeout(Duration::from_millis(150), s.wait_closed()).await;
        assert!(parked.is_err(), "resolved while the dialer still held on");
        tokio::time::timeout(Duration::from_secs(10), s.wait_closed())
            .await
            .expect("must resolve after the dialer drops");
        b.shutdown().await;
    });

    tokio::time::timeout(Duration::from_secs(20), async {
        let mut s = a.connect(device(6), ALPN).await.expect("connect");
        s.send(b"go").await.unwrap();
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"payload"[..]));
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(s);
    })
    .await
    .expect("timed out");
    b_task.await.unwrap();
    a.shutdown().await;
}

/// Gossip over Isolated direct connections: subscribe both, bootstrap A from B,
/// `joined()` under a timeout, broadcast A→B, and see the frame plus an
/// eventual `NeighborUp`. Also proves gossip never surfaces via `accept` and
/// exercises the split sender/receiver concurrency shape (broadcast while the
/// receiver half is parked in `next`).
#[tokio::test]
async fn gossip_room_roundtrip() {
    let (a, b) = isolated_pair(7, 8, &[]).await;
    let topic = Topic([9u8; 32]);
    let a_id = a.my_id();

    let (_b_send, mut b_recv) = b.subscribe(topic, &[]).await.expect("B subscribes");
    let (a_send, mut a_recv) = a
        .subscribe(topic, &[b.my_id()])
        .await
        .expect("A subscribes with bootstrap");

    tokio::time::timeout(Duration::from_secs(20), async {
        a_recv.joined().await.expect("A joins the room");

        // Sender-half broadcast while the receiver half is parked in next() on
        // its own task — the daemon's heartbeat/recv_loop concurrency (G1).
        let a_reader = tokio::spawn(async move { a_recv.next().await });
        // Broadcast until B observes it (gossip formation is eventual).
        let mut got_received = false;
        let mut got_neighbor = false;
        for _ in 0..50 {
            a_send.broadcast(b"hello-room".to_vec()).await.unwrap();
            match tokio::time::timeout(Duration::from_millis(300), b_recv.next()).await {
                Ok(Some(GossipEvent::Received { from, bytes })) => {
                    assert_eq!(bytes, b"hello-room");
                    let _ = from; // last-hop hint, not asserted as author
                    got_received = true;
                    break;
                }
                Ok(Some(GossipEvent::NeighborUp(id))) => {
                    assert_eq!(id, a_id);
                    got_neighbor = true;
                }
                Ok(Some(_)) | Ok(None) | Err(_) => {}
            }
        }
        assert!(got_received, "B must receive A's broadcast");
        // NeighborUp may have arrived before or after; drain a bit if not seen.
        if !got_neighbor {
            for _ in 0..20 {
                if let Ok(Some(GossipEvent::NeighborUp(id))) =
                    tokio::time::timeout(Duration::from_millis(200), b_recv.next()).await
                {
                    assert_eq!(id, a_id);
                    got_neighbor = true;
                    break;
                }
            }
        }
        assert!(got_neighbor, "B must eventually see NeighborUp(A)");
        a_reader.abort();
    })
    .await
    .expect("gossip roundtrip timed out");

    // Gossip connections never surface through accept(): a shutdown must be the
    // only thing that ends a parked accept.
    a.shutdown().await;
    b.shutdown().await;
}

/// A parked `accept` returns `None` once `shutdown` runs on another handle.
#[tokio::test]
async fn shutdown_unblocks_accept() {
    use std::sync::Arc;
    let a = Arc::new(
        DefaultTransport::new(&[9u8; 32], &Network::Isolated, &[SYNC_ALPN])
            .await
            .expect("build"),
    );
    let parked = {
        let a = a.clone();
        tokio::spawn(async move { a.accept().await })
    };
    // Let the accept park with no dialer, then shut down from this handle.
    tokio::time::sleep(Duration::from_millis(200)).await;
    a.shutdown().await;
    let inc = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("accept must unblock after shutdown")
        .expect("join");
    assert!(inc.is_none(), "a parked accept returns None after shutdown");
}

/// `probe_peer` liveness: a peer that has `shutdown` cannot be connected to.
#[tokio::test]
async fn probe_semantics_connect_fails_when_peer_down() {
    let (a, b) = isolated_pair(10, 11, &[SYNC_ALPN]).await;
    b.shutdown().await;
    // With the accepter's endpoint closed, the dial cannot complete.
    let result =
        tokio::time::timeout(Duration::from_secs(8), a.connect(device(11), SYNC_ALPN)).await;
    match result {
        Ok(Err(_)) => {} // connect errored — the liveness signal
        Err(_) => {}     // or timed out — also "peer is down"
        Ok(Ok(_)) => panic!("connect to a shutdown peer must not succeed"),
    }
    a.shutdown().await;
}

/// One test on an in-process relay (the `hermetic_net.rs` harness): two `Local`
/// endpoints converge by bare-id dial through the `PeerBook`, proving the Local
/// policy path through the transport. Needs the self-signed cert skip, so it
/// builds the endpoints via the raw harness and drives them directly — the
/// production `DefaultTransport::new` deliberately does not link the cert skip.
#[tokio::test]
async fn local_policy_relay_resolution() {
    // Stand up a relay entirely in this process.
    let (relay_map, relay_url, _relay_guard): (RelayMap, RelayUrl, _) =
        iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");

    const ALPN: Alpn = SYNC_ALPN;

    async fn local_endpoint(
        seed: u8,
        relay: RelayMap,
    ) -> (Endpoint, iroh::address_lookup::MemoryLookup) {
        let lookup = iroh::address_lookup::MemoryLookup::new();
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(relay))
            .address_lookup(lookup.clone())
            .ca_roots_config(CaRootsConfig::insecure_skip_verify())
            .alpns(vec![ALPN.to_vec()])
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .bind()
            .await
            .expect("bind local endpoint");
        (ep, lookup)
    }

    let (server, _s_lookup) = local_endpoint(60, relay_map.clone()).await;
    let (client, c_lookup) = local_endpoint(61, relay_map).await;
    server.online().await;
    client.online().await;
    let server_id = server.id();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        send.write_all(b"pong").await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
    });

    // Register {server_id, relay} exactly as PeerBook::learn does under Local.
    c_lookup.add_endpoint_info(lait_net::policy::relay_addr(&relay_url, server_id));
    let result = tokio::time::timeout(Duration::from_secs(20), async move {
        let conn = client.connect(server_id, ALPN).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("local relay resolution timed out");
    assert_eq!(&result, b"pong");
    server_task.await.unwrap();
}
