//! Per-peer presence state machine.
//!
//! Presence is driven by the gossip *membership* signal (NeighborUp/Down) and a
//! direct liveness probe — NOT by whether periodic heartbeats are delivered.
//! The gossip overlay uses a Plumtree broadcast tree that, in a small room, prunes the
//! link to "lazy push" after the first exchange, so heartbeats are only
//! delivered in ~100s bursts even though the peer stays continuously connected.
//! Timing presence off heartbeat delivery therefore flaps a live peer offline
//! every ~30s. We instead treat a peer as online while it is a neighbor, drop it
//! to `Suspect` on NeighborDown, and confirm with a direct probe before
//! declaring `Offline`.

use std::time::{Duration, Instant};

/// The ALPN a liveness probe dials. It is a lait protocol name, not transport
/// mechanism, and it lives beside the probe's semantics.
///
/// It moves in lockstep with [`crate::sync::SYNC_ALPN`] and the gossip topic
/// tag, so a version skew that partitions sync and gossip also partitions the
/// liveness probe rather than leaving cross-epoch peers half-visible. Epoch 1
/// carried the space-identity rewrite and the sync `protocol_version`
/// handshake; epoch 2 carries the space-vocabulary flag day.
pub const PRESENCE_ALPN: &[u8] = b"lait/presence/2";

/// Grace period after a NeighborDown (with no probe result yet) before a peer is
/// declared offline. Covers the large-mesh case where NeighborDown means "no
/// longer my *direct* neighbor" rather than "left the room".
pub const SUSPECT_WINDOW: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Online,
    /// Neighbor link dropped; a direct probe is in flight. Still shown as online
    /// to the user (no alarm) until confirmed dead or the suspect window lapses.
    Suspect,
    Offline,
}

/// Presence state for a single peer. Pure logic: all time is passed in, so it is
/// fully unit-testable without any networking.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub state: Presence,
    suspect_since: Option<Instant>,
}

impl PeerState {
    /// A peer first seen alive (NeighborUp or any received traffic).
    pub fn new_online(_now: Instant) -> Self {
        PeerState {
            state: Presence::Online,
            suspect_since: None,
        }
    }

    /// Any positive liveness signal (NeighborUp or a received message). Returns
    /// true if this made the peer newly *visible* as online (was Offline).
    pub fn seen(&mut self, _now: Instant) -> bool {
        let was_visible = self.is_online();
        self.state = Presence::Online;
        self.suspect_since = None;
        !was_visible
    }

    /// The gossip layer dropped this peer as a direct neighbor. Returns true if
    /// this transitioned an online peer into Suspect (i.e. launch a probe).
    pub fn neighbor_down(&mut self, now: Instant) -> bool {
        if self.state == Presence::Online {
            self.state = Presence::Suspect;
            self.suspect_since = Some(now);
            true
        } else {
            false
        }
    }

    /// Result of a direct liveness probe. Returns Some(true) if the peer became
    /// visibly online again, Some(false) if it became visibly offline, None if
    /// there was no visible transition.
    pub fn probe_result(&mut self, alive: bool, now: Instant) -> Option<bool> {
        if alive {
            let was_visible = self.is_online();
            self.seen(now);
            if was_visible {
                None
            } else {
                Some(true)
            }
        } else if self.force_offline() {
            Some(false)
        } else {
            None
        }
    }

    /// A graceful Bye, or any forced offline. Returns true if the peer was
    /// visibly online (so a "went offline" notice should fire).
    pub fn force_offline(&mut self) -> bool {
        let was_visible = self.is_online();
        self.state = Presence::Offline;
        self.suspect_since = None;
        was_visible
    }

    /// Whether a suspect peer has exceeded the grace window with no probe result
    /// and should now be declared offline by the reaper.
    pub fn should_reap(&self, now: Instant) -> bool {
        match (self.state, self.suspect_since) {
            (Presence::Suspect, Some(since)) => now.duration_since(since) >= SUSPECT_WINDOW,
            _ => false,
        }
    }

    /// Shown to the user as "online"? Suspect counts as online (no premature
    /// alarm); only Offline is offline.
    pub fn is_online(&self) -> bool {
        matches!(self.state, Presence::Online | Presence::Suspect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn connected_peer_stays_online_without_any_heartbeats() {
        // The core regression: a peer that is up and sends nothing must NOT be
        // reaped, no matter how long, as long as it never NeighborDowns.
        let t0 = Instant::now();
        let p = PeerState::new_online(t0);
        assert!(p.is_online());
        assert!(
            !p.should_reap(at(t0, 300)),
            "a connected peer must never be reaped on a timer"
        );
    }

    #[test]
    fn neighbor_down_enters_suspect_still_shown_online() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        let became_suspect = p.neighbor_down(at(t0, 10));
        assert!(
            became_suspect,
            "online -> NeighborDown should become Suspect"
        );
        assert_eq!(p.state, Presence::Suspect);
        assert!(
            p.is_online(),
            "suspect is still shown online until confirmed"
        );
    }

    #[test]
    fn probe_alive_keeps_online_no_visible_flap() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        p.neighbor_down(at(t0, 10));
        let transition = p.probe_result(true, at(t0, 11));
        assert_eq!(p.state, Presence::Online);
        assert_eq!(
            transition, None,
            "suspect->online via probe is not a visible flap"
        );
    }

    #[test]
    fn probe_dead_marks_offline_visibly() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        p.neighbor_down(at(t0, 10));
        let transition = p.probe_result(false, at(t0, 11));
        assert_eq!(p.state, Presence::Offline);
        assert_eq!(
            transition,
            Some(false),
            "a dead probe is a visible went-offline"
        );
        assert!(!p.is_online());
    }

    #[test]
    fn suspect_times_out_to_offline_if_probe_never_returns() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        p.neighbor_down(at(t0, 10));
        assert!(!p.should_reap(at(t0, 10)), "not immediately");
        assert!(
            p.should_reap(at(t0, 10) + SUSPECT_WINDOW + Duration::from_secs(1)),
            "after the suspect window with no probe result -> reap"
        );
    }

    #[test]
    fn received_traffic_clears_suspect() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        p.neighbor_down(at(t0, 10));
        assert_eq!(p.state, Presence::Suspect);
        let came_online = p.seen(at(t0, 12));
        assert_eq!(p.state, Presence::Online);
        assert!(
            !came_online,
            "was already shown online (suspect), so no new online notice"
        );
    }

    #[test]
    fn seen_from_offline_is_a_visible_online() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        p.force_offline();
        assert!(!p.is_online());
        let came_online = p.seen(at(t0, 5));
        assert!(came_online, "offline -> seen is a visible came-online");
        assert_eq!(p.state, Presence::Online);
    }

    #[test]
    fn force_offline_is_visible_only_when_was_online() {
        let t0 = Instant::now();
        let mut p = PeerState::new_online(t0);
        assert!(p.force_offline(), "online -> offline is visible");
        assert!(
            !p.force_offline(),
            "offline -> offline is not visible again"
        );
    }
}
