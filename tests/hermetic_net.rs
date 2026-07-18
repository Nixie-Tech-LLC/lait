//! Proof of the network-policy seam (`lait::net`): lait owns its transport
//! environment, so it can run **hermetically** — on an in-process relay, with no
//! public internet and no n0 infrastructure. This is the operational ownership
//! the seam buys, and the foundation for making the two-node daemon tests (and
//! CI) deterministic instead of hostage to the public relay.
//!
//! It asserts two things:
//!  1. `build_endpoint` maps every policy to a bindable endpoint (Public, Local,
//!     Isolated) — the production function, exercised directly.
//!  2. Two endpoints configured exactly as lait's `Local` policy configures them
//!     converge over an in-process relay and exchange bytes — offline.
//!
//! The self-signed in-process relay needs cert-verification skipped, which iroh
//! gates to test builds; that lives here (a dev-dependency), never in the
//! shipped `build_endpoint`.

use std::time::Duration;

use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_relay::tls::CaRootsConfig;
use lait::net::{build_endpoint, LocalNet, Network};

const TEST_ALPN: &[u8] = b"lait/hermetic-test/1";

/// A `Local`-policy endpoint for the test: the SAME iroh config `build_endpoint`
/// produces for `Network::Local` (Minimal preset + a custom relay map), plus the
/// two things a raw test needs that the daemon supplies elsewhere — the test
/// ALPN, and cert-skip for the in-process relay's self-signed certificate.
async fn local_test_endpoint(seed: [u8; 32], relay: RelayMap) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay))
        .ca_roots_config(CaRootsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()])
        .secret_key(SecretKey::from_bytes(&seed))
        .bind()
        .await
        .expect("bind local test endpoint")
}

#[tokio::test]
async fn build_endpoint_binds_every_policy() {
    // Isolated: no relay, no discovery — must bind with zero infrastructure.
    let iso = build_endpoint(&SecretKey::from_bytes(&[1u8; 32]), &Network::Isolated).await;
    assert!(iso.is_ok(), "Isolated must bind offline: {iso:?}");

    // Local: a custom relay. Binding does not contact the relay, so any URL binds.
    let local = build_endpoint(
        &SecretKey::from_bytes(&[2u8; 32]),
        &Network::Local(LocalNet {
            relay: "https://relay.invalid".to_string(),
        }),
    )
    .await;
    assert!(local.is_ok(), "Local must bind: {local:?}");

    // from_env default is Public and must not error to construct.
    assert!(matches!(Network::from_env(), Ok(Network::Public)));
}

#[tokio::test]
async fn two_local_endpoints_converge_over_an_in_process_relay() {
    // Stand up a relay entirely in this process — no public internet.
    let (relay_map, relay_url, _relay_guard): (RelayMap, RelayUrl, _) =
        iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");

    let server = local_test_endpoint([11u8; 32], relay_map.clone()).await;
    let client = local_test_endpoint([22u8; 32], relay_map).await;
    // Both must have a working relay path before they can be reached by id.
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

    // Client: reach the server by id, via the relay (address-free — the relay
    // provides reachability, exactly as lait's Local policy intends).
    let addr = EndpointAddr::new(server_id).with_relay_url(relay_url);
    let result = tokio::time::timeout(Duration::from_secs(20), async move {
        let conn = client.connect(addr, TEST_ALPN).await.expect("connect");
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
        "the two endpoints converged over the local relay"
    );
    server_task.await.expect("server task");
}
