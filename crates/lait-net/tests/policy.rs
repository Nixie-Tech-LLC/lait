//! Tests for the network-policy seam (`lait_net::policy`), driven through lait's REAL
//! reachability path.
//!
//! Under `Local`, lait dials peers by **bare `EndpointId`** (its address-free
//! design) and resolves them through a `MemoryLookup` it populates with
//! `{id, relay}` — the address lait already knows because it configured the
//! relay. No discovery service, plaintext or otherwise, exists to fake. These
//! tests use exactly that construction (`lait_net::policy::relay_addr` + a
//! `MemoryLookup`, then `connect(bare_id)`), so a green result reflects the
//! daemon's actual mechanism, not an iroh feature.
//!
//! The self-signed in-process relay needs cert-verification skipped, which iroh
//! gates to test builds; that lives here (a dev-dependency), never in the
//! shipped `build_endpoint`.

use std::net::SocketAddr;
use std::time::Duration;

use iroh::{
    address_lookup::MemoryLookup, endpoint::presets, Endpoint, RelayMap, RelayMode, RelayUrl,
    SecretKey,
};
use iroh_relay::tls::CaRootsConfig;
use lait_net::policy::{build_endpoint, relay_addr, LocalNet, Network};

const TEST_ALPN: &[u8] = b"lait/hermetic-test/1";

/// A `Local`-policy endpoint for the test: the SAME shape `build_endpoint`
/// produces for `Network::Local` — `presets::Minimal` + a custom relay + a
/// `MemoryLookup` for bare-id resolution — plus the two things a raw test needs
/// that the daemon supplies elsewhere: the test ALPN, and cert-skip for the
/// in-process relay's self-signed certificate. Returns the lookup so the test
/// can register peers exactly as the daemon's `PeerBook` does.
async fn local_test_endpoint(seed: [u8; 32], relay: RelayMap) -> (Endpoint, MemoryLookup) {
    let lookup = MemoryLookup::new();
    let ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay))
        .address_lookup(lookup.clone())
        .ca_roots_config(CaRootsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()])
        .secret_key(SecretKey::from_bytes(&seed))
        .bind()
        .await
        .expect("bind local test endpoint");
    (ep, lookup)
}

#[tokio::test]
async fn build_endpoint_binds_every_policy() {
    // Isolated: no relay, no discovery — must bind with zero infrastructure.
    let iso = build_endpoint(&SecretKey::from_bytes(&[1u8; 32]), &Network::Isolated).await;
    assert!(iso.is_ok(), "Isolated must bind offline: {:?}", iso.err());

    // Local: a custom relay. Binding does not contact the relay, so any URL binds.
    let local = build_endpoint(
        &SecretKey::from_bytes(&[2u8; 32]),
        &Network::Local(LocalNet {
            relay: "https://relay.invalid".to_string(),
        }),
    )
    .await;
    assert!(local.is_ok(), "Local must bind: {:?}", local.err());

    // from_env default is Public and must not error to construct.
    assert!(matches!(Network::from_env(), Ok(Network::Public)));
}

/// The real thing: two `Local` endpoints converge by **bare-id dial** over an
/// in-process relay — no public internet, no discovery service — because each
/// registers the other as `{id, relay}` via lait's own `relay_addr`, exactly as
/// the daemon's `PeerBook` does on every peer it learns.
#[tokio::test]
async fn local_endpoints_converge_by_bare_id_over_an_in_process_relay() {
    // Stand up a relay entirely in this process — no public internet.
    let (relay_map, relay_url, _relay_guard): (RelayMap, RelayUrl, _) =
        iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");

    let (server, _server_lookup) = local_test_endpoint([11u8; 32], relay_map.clone()).await;
    let (client, client_lookup) = local_test_endpoint([22u8; 32], relay_map).await;
    server.online().await;
    client.online().await;
    let server_id = server.id();

    // Server: accept one connection and echo a byte string back.
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming");
        let conn = incoming.await.expect("accept conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept bi");
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.expect("read ping");
        assert_eq!(&buf, b"ping");
        send.write_all(b"pong").await.expect("write pong");
        send.finish().expect("finish");
        conn.closed().await;
    });

    // Teach the client how to reach the server the way the daemon does: register
    // `{server_id, relay}` via lait's own address construction …
    client_lookup.add_endpoint_info(relay_addr(&relay_url, server_id));
    // … then dial by BARE ID — the production path. Resolution goes through the
    // MemoryLookup we just populated; no address is hand-carried into `connect`.
    let result = tokio::time::timeout(Duration::from_secs(20), async move {
        let conn = client.connect(server_id, TEST_ALPN).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"ping").await.expect("write ping");
        send.finish().expect("finish");
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.expect("read pong");
        buf
    })
    .await
    .expect("hermetic round trip timed out");

    assert_eq!(
        &result, b"pong",
        "two Local endpoints converged by bare-id dial over the local relay"
    );
    server_task.await.expect("server task");
}

/// `Isolated`, end-to-end through the PRODUCTION code: two endpoints built by the
/// real `build_endpoint(Isolated)` connect by **bare-id dial** on loopback with
/// NO relay and NO discovery — the client registers the server's carried direct
/// address via the real `PeerBook::learn_direct` (the ticket path). No relay
/// means no self-signed cert, so this needs no test-only TLS skip at all.
#[tokio::test]
async fn isolated_endpoints_converge_by_carried_direct_address() {
    let (server, _server_peers) =
        build_endpoint(&SecretKey::from_bytes(&[33u8; 32]), &Network::Isolated)
            .await
            .expect("build isolated server");
    let (client, client_peers) =
        build_endpoint(&SecretKey::from_bytes(&[44u8; 32]), &Network::Isolated)
            .await
            .expect("build isolated client");
    server.set_alpns(vec![TEST_ALPN.to_vec()]);
    let server_id = server.id();
    // The addresses a ticket would carry under Isolated.
    let server_addrs: Vec<SocketAddr> = server.addr().ip_addrs().copied().collect();
    assert!(
        !server_addrs.is_empty(),
        "an Isolated endpoint must expose direct addresses to advertise"
    );

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming");
        let conn = incoming.await.expect("accept conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept bi");
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.expect("read ping");
        send.write_all(b"pong").await.expect("write pong");
        send.finish().expect("finish");
        conn.closed().await;
    });

    // Register the host's carried addresses exactly as the join path does, then
    // dial by BARE ID — resolution goes through the direct address, no relay.
    client_peers.learn_direct(server_id, &server_addrs);
    let result = tokio::time::timeout(Duration::from_secs(20), async move {
        let conn = client.connect(server_id, TEST_ALPN).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"ping").await.expect("write ping");
        send.finish().expect("finish");
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.expect("read pong");
        buf
    })
    .await
    .expect("isolated round trip timed out");

    assert_eq!(
        &result, b"pong",
        "two Isolated endpoints converged by bare-id dial over a carried address"
    );
    server_task.await.expect("server task");
}
