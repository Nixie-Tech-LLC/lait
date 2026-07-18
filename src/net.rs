//! **Network policy** — lait's own requirement for the transport environment,
//! with iroh as the contractor that fulfils it.
//!
//! lait states *where* it operates — the public relay mesh, a named local relay,
//! or isolated — and this module is the **single place** iroh's relay/discovery
//! vocabulary (`RelayMode`, `presets`, `address_lookup`) is spoken. Above
//! [`build_endpoint`] the rest of the daemon knows only [`Network`]; there is no
//! "iroh default" anymore, only lait's `Public` policy that iroh executes.
//!
//! The point is ownership of *behaviour*: with this seam lait chooses its relay
//! and discovery (self-hosted, or a test harness's in-process servers) instead
//! of inheriting n0's — which is what makes hermetic, offline, deterministic
//! multi-node testing possible.

use anyhow::{Context, Result};
use iroh::{
    address_lookup::MemoryLookup, endpoint::presets, Endpoint, RelayMap, RelayMode, RelayUrl,
    SecretKey,
};

/// lait's requirement for the transport environment. iroh executes it.
#[derive(Debug, Clone)]
pub enum Network {
    /// The public relay mesh + public discovery (n0). The default — unchanged
    /// behaviour, now stated rather than inherited.
    Public,
    /// A relay + discovery service lait supplies — a self-hosted deployment or a
    /// test harness's in-process servers. Hermetic: no public internet.
    Local(LocalNet),
    /// No relay, no discovery — direct reach only. Peers must carry addresses
    /// (a separate slice, reversing the address-free ticket design); endpoint
    /// construction is defined here, but address-free connectivity is not yet
    /// wired, so this is not usable for the daemon's join flow today.
    Isolated,
}

/// A self-hosted or test network lait reaches peers through. With a single known
/// relay, reachability is relay-based (a peer is `{its id, this relay}`) — no
/// public discovery needed, which is exactly what makes it hermetic. lait names
/// the relay in a plain URL; iroh is the contractor.
#[derive(Debug, Clone)]
pub struct LocalNet {
    /// The relay URL peers rendezvous through (`https://…` / `http://…`). A
    /// self-hosted relay presenting a valid certificate. (Self-signed / dev
    /// relays require skipping cert verification, which iroh gates to test
    /// builds — so that path lives in the test harness, not here.)
    pub relay: String,
}

impl Network {
    /// Resolve the requirement from the environment, defaulting to [`Public`] so
    /// existing deployments are unchanged. `LAIT_NETWORK` = `public` (default) |
    /// `local` | `isolated`; `local` additionally reads `LAIT_RELAY`,
    /// `LAIT_PKARR`, `LAIT_DNS` (host:port) and optional `LAIT_NET_ORIGIN`.
    ///
    /// [`Public`]: Network::Public
    pub fn from_env() -> Result<Self> {
        match std::env::var("LAIT_NETWORK").ok().as_deref() {
            None | Some("") | Some("public") => Ok(Network::Public),
            Some("isolated") => Ok(Network::Isolated),
            Some("local") => Ok(Network::Local(LocalNet {
                relay: env_req("LAIT_RELAY")?,
            })),
            Some(other) => {
                anyhow::bail!("unknown LAIT_NETWORK '{other}' (expected public|local|isolated)")
            }
        }
    }

    /// Whether this policy provides a relay — so waiting on `endpoint.online()`
    /// (which blocks on a home relay) is sound. Isolated has none.
    pub fn uses_relay(&self) -> bool {
        !matches!(self, Network::Isolated)
    }
}

fn env_req(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("LAIT_NETWORK=local requires {key}"))
}

/// Build the iroh endpoint that fulfils lait's [`Network`]. This is the sole
/// contractor boundary: the only function in the codebase that names iroh's
/// relay and discovery types. A future transport swap rewrites this and nothing
/// above it.
pub async fn build_endpoint(secret_key: &SecretKey, net: &Network) -> Result<Endpoint> {
    let builder = match net {
        // Public: n0's relays + discovery, plus the in-process address cache the
        // daemon has always used.
        Network::Public => Endpoint::builder(presets::N0).address_lookup(MemoryLookup::new()),
        // Isolated: no relay, no discovery. Direct reach only.
        Network::Isolated => Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup(),
        // Local: lait's own single relay. Reachability is relay-based (a peer is
        // `{its id, this relay}`), so no public discovery is involved — that is
        // what makes it hermetic and offline-capable.
        Network::Local(l) => {
            let relay: RelayUrl = l.relay.parse().context("LAIT_RELAY is not a valid URL")?;
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(RelayMap::from(relay)))
        }
    };
    builder
        .secret_key(secret_key.clone())
        .bind()
        .await
        .context("bind iroh endpoint")
}
