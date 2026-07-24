//! Coordinates v1 — the canonical, verifiable material to identify and approach
//! a Space. This is S2's replacement for the pre-carve join ticket: a signed,
//! self-describing envelope with a fixed postcard tuple layout, a length-framed
//! signature preimage, strict bounds, and an exhaustive malformed/substitution
//! rejection matrix.
//!
//! Formation is verified as the **self-authenticating proof committed by the
//! SpaceId** (the founder inception), independent of the approach Station's
//! outer signature. The outer signature (domain `lait/coordinates/1`) proves the
//! approach Station vouches for the routing hints; `issuer` must equal
//! `approach_station`. An optional [`AdmissionCapability`] (domain
//! `lait/admission/1`) is separately authority-signed; possession only
//! authorizes a *request* — standing exists only after mechanics validates
//! incorporated authority material at redemption.
//!
//! The old ticket tag/domain is rejected with
//! [`CoordinatesError::UnsupportedVersion`]; there is no migration.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use mechanics::actor::SignedEvent;
use mechanics::ids::{ActorId, DeviceId, SpaceId};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// The outer signature domain.
pub const COORDINATES_DOMAIN: &[u8] = b"lait/coordinates/2";
/// The admission-capability signature domain.
pub const ADMISSION_DOMAIN: &[u8] = b"lait/admission/1";
/// Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;

/// Maximum decoded Coordinates size.
pub const MAX_DECODED: usize = 64 * 1024;
/// Maximum canonical founder-inception size.
pub const MAX_INCEPTION: usize = 32 * 1024;
/// Maximum display-name-hint bytes.
pub const MAX_NAME: usize = 128;
/// Maximum approach-nick-hint bytes.
pub const MAX_NICK: usize = 64;
/// Maximum approach addresses.
pub const MAX_ADDRS: usize = 8;
/// The fixed byte length of a rendered SpaceId (`ws_` + 26 Crockford chars).
pub const SPACE_ID_LEN: usize = 29;

/// A signed direct route to the approach Station. Tag 0 = DirectV4, tag 1 =
/// DirectV6 (postcard variant order). Relay/discovery configuration is guarded
/// local transport policy and never travels here — a route is always a direct,
/// dialable IP + port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ApproachRoute {
    DirectV4 { ip: [u8; 4], port: u16 },
    DirectV6 { ip: [u8; 16], port: u16 },
}

impl ApproachRoute {
    pub fn from_socket(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => ApproachRoute::DirectV4 {
                ip: a.ip().octets(),
                port: a.port(),
            },
            SocketAddr::V6(a) => ApproachRoute::DirectV6 {
                ip: a.ip().octets(),
                port: a.port(),
            },
        }
    }
    pub fn to_socket(&self) -> SocketAddr {
        match self {
            ApproachRoute::DirectV4 { ip, port } => {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(*ip), *port))
            }
            ApproachRoute::DirectV6 { ip, port } => {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(*ip), *port, 0, 0))
            }
        }
    }

    /// Whether this route is a usable, dialable direct address: a non-zero
    /// port and a specified, non-multicast unicast IP.
    pub fn is_usable(&self) -> bool {
        match self {
            ApproachRoute::DirectV4 { ip, port } => {
                let ip = Ipv4Addr::from(*ip);
                *port != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
            }
            ApproachRoute::DirectV6 { ip, port } => {
                let ip = Ipv6Addr::from(*ip);
                *port != 0 && !ip.is_unspecified() && !ip.is_multicast()
            }
        }
    }
}

/// Canonicalize a set of dialable socket addresses into signed
/// [`ApproachRoute`]s: drop unusable addresses (unspecified, multicast,
/// broadcast, zero-port), sort by their canonical encoding (tag then value),
/// deduplicate, and bound to [`MAX_ADDRS`]. This is what invite creation runs
/// before mechanics signs the final vector.
pub fn canonical_routes(addrs: &[SocketAddr]) -> Vec<ApproachRoute> {
    let mut routes: Vec<ApproachRoute> = addrs
        .iter()
        .map(ApproachRoute::from_socket)
        .filter(ApproachRoute::is_usable)
        .collect();
    routes.sort();
    routes.dedup();
    routes.truncate(MAX_ADDRS);
    routes
}

/// The admission slot. Tag 0 = None, tag 1 = Some (postcard variant order).
/// The capability is boxed so the enum stays small (the capability carries the
/// role-expansion evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinatesAdmission {
    None,
    Some(Box<AdmissionCapability>),
}

/// How many times an admission capability may be redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionUsePolicy {
    /// Exactly one binding admits.
    SingleUse,
    /// Up to `max_redemptions` (2..=1024) distinct candidate bindings admit.
    Reusable { max_redemptions: u16 },
}

impl AdmissionUsePolicy {
    /// The redemption cap this policy allows.
    pub fn cap(&self) -> u32 {
        match self {
            AdmissionUsePolicy::SingleUse => 1,
            AdmissionUsePolicy::Reusable { max_redemptions } => *max_redemptions as u32,
        }
    }
    fn is_valid(&self) -> bool {
        match self {
            AdmissionUsePolicy::SingleUse => true,
            AdmissionUsePolicy::Reusable { max_redemptions } => {
                (2..=1024).contains(max_redemptions)
            }
        }
    }
}

/// The signed pre-authorization to request admission (wire version 2).
/// Accepting valid Coordinates **is** the approval — there is no approval
/// policy field. It carries the use policy, its validity window, and the
/// generic [`WorldAssignmentEvidence`] role expansion redemption installs. Its
/// issuer authority, time window, reuse cap, and evidence delegability are
/// validated by mechanics **at redemption**; here only structure, time-bound
/// shape, and the self-signature are checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCapability {
    pub version: u8,
    pub space: [u8; SPACE_ID_LEN],
    pub issuer: [u8; 32],
    /// The capability id / revocation key.
    pub nonce: [u8; 16],
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub use_policy: AdmissionUsePolicy,
    /// The generic role expansion redemption installs (opaque to Mechanics
    /// beyond its generic assignments).
    pub evidence: mechanics::demand::WorldAssignmentEvidence,
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// The signed payload of Coordinates. Field order is the canonical tuple layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatesPayload {
    pub space: [u8; SPACE_ID_LEN],
    pub salt: [u8; 16],
    pub recovery_root: [u8; 32],
    /// Canonical `SignedEvent` bytes (postcard), <= 32 KiB.
    pub founder_inception: Vec<u8>,
    pub display_name_hint: String,
    pub approach_station: [u8; 32],
    pub approach_nick_hint: String,
    pub approach_routes: Vec<ApproachRoute>,
    pub admission: CoordinatesAdmission,
}

/// The full signed Coordinates envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCoordinates {
    pub version: u8,
    pub payload: CoordinatesPayload,
    pub issuer: [u8; 32],
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// Why Coordinates (or an admission) failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatesError {
    /// The version tag was not 2 (covers Coordinates v1 and a pre-carve
    /// join ticket) — rejected, never negotiated.
    UnsupportedVersion(u8),
    /// The signature algorithm was not Ed25519.
    UnsupportedSignatureAlgorithm(u8),
    /// The bytes did not decode, exceeded the size bound, left trailing bytes,
    /// or were non-canonical (decode/re-encode mismatch).
    NonCanonical,
    /// The base32 link form was unreadable.
    BadLink,
    /// The `space` field was not a valid rendered SpaceId.
    BadSpaceId,
    /// `issuer` did not equal `approach_station`.
    IssuerMismatch,
    /// A display-name/nick hint exceeded its bound or was not NFC.
    BadNameHint,
    /// The founder inception exceeded its size bound.
    InceptionTooLarge,
    /// The founder inception did not decode, or the SpaceId does not commit to
    /// it (formation self-proof failed).
    FoundingInvalid,
    /// Approach addresses exceeded the count bound, or were unsorted/duplicated.
    BadAddresses,
    /// The outer or admission signature did not verify.
    BadSignature,
    /// The admission capability was malformed or bound to another Space.
    BadAdmission,
}

impl std::fmt::Display for CoordinatesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CoordinatesError {}

/// The result of verifying Coordinates: the identified Space and its approach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCoordinates {
    pub space: SpaceId,
    pub founder_actor: ActorId,
    pub approach_station: DeviceId,
    pub display_name_hint: String,
    pub approach_nick_hint: String,
    pub approach_routes: Vec<SocketAddr>,
    /// A structurally-valid, correctly-signed admission bound to this Space.
    /// Authority/expiry/nonce-use are validated by mechanics at redemption.
    pub admission: Option<AdmissionCapability>,
}

/// Build the length-framed preimage `u16be(domain_len) || domain ||
/// u32be(body_len) || body`.
fn length_framed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + 4 + body.len());
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn is_nfc(s: &str) -> bool {
    s.chars().eq(s.nfc())
}

/// The rendered-SpaceId bytes for a [`SpaceId`], if it is exactly 29 bytes.
fn space_id_bytes(space: &SpaceId) -> Option<[u8; SPACE_ID_LEN]> {
    <[u8; SPACE_ID_LEN]>::try_from(space.as_str().as_bytes()).ok()
}

/// Parse the 29 fixed bytes back to a validated [`SpaceId`].
fn space_id_from_bytes(bytes: &[u8; SPACE_ID_LEN]) -> Option<SpaceId> {
    let s = std::str::from_utf8(bytes).ok()?;
    SpaceId::parse(s)
}

impl AdmissionCapability {
    fn preimage(&self) -> Vec<u8> {
        let body = postcard::to_stdvec(&(
            self.version,
            self.space,
            self.issuer,
            self.nonce,
            self.issued_at,
            self.not_before,
            self.expires_at,
            self.use_policy,
            self.evidence.digest(),
        ))
        .expect("postcard admission body");
        length_framed(ADMISSION_DOMAIN, &body)
    }

    /// Mint and sign an admission capability from the issuing device's seed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        space: &SpaceId,
        nonce: [u8; 16],
        issued_at: u64,
        not_before: u64,
        expires_at: u64,
        use_policy: AdmissionUsePolicy,
        evidence: mechanics::demand::WorldAssignmentEvidence,
        issuer_seed: &[u8; 32],
    ) -> Option<Self> {
        let issuer = mechanics::crypto::device_from_seed(issuer_seed).key_bytes()?;
        let mut cap = Self {
            version: 2,
            space: space_id_bytes(space)?,
            issuer,
            nonce,
            issued_at,
            not_before,
            expires_at,
            use_policy,
            evidence,
            signature_algorithm: SIG_ALG_ED25519,
            signature: [0u8; 64],
        };
        cap.signature = mechanics::crypto::sign_detached(issuer_seed, &cap.preimage());
        Some(cap)
    }

    /// The capability id: BLAKE3 over its full signed bytes (a stable handle
    /// the acceptance proof binds to).
    pub fn capability_id(&self) -> [u8; 32] {
        blake3::derive_key(
            "lait.admission-capability.v1",
            &postcard::to_stdvec(self).expect("postcard admission capability"),
        )
    }

    /// Verify structure + self-signature + evidence shape + time-bound shape,
    /// and that it is bound to `space`. Authority, the exact time window, reuse
    /// cap, and evidence delegability are the redeemer's (mechanics) checks.
    pub fn verify_structure(&self, space: &SpaceId) -> Result<(), CoordinatesError> {
        if self.version != 2 {
            return Err(CoordinatesError::UnsupportedVersion(self.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(CoordinatesError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        if space_id_bytes(space).as_ref() != Some(&self.space) {
            return Err(CoordinatesError::BadAdmission);
        }
        if !self.use_policy.is_valid() || self.not_before > self.expires_at {
            return Err(CoordinatesError::BadAdmission);
        }
        if self.evidence.validate().is_err() {
            return Err(CoordinatesError::BadAdmission);
        }
        if !mechanics::crypto::verify_detached(&self.issuer, &self.preimage(), &self.signature) {
            return Err(CoordinatesError::BadSignature);
        }
        Ok(())
    }

    /// Whether the capability's validity window contains `now` (unix seconds).
    pub fn is_within_window(&self, now: u64) -> bool {
        now >= self.not_before && now < self.expires_at
    }

    /// Whether the capability has expired relative to `now` (unix seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// The signature domain for an invitation-acceptance proof.
pub const ACCEPT_DOMAIN: &[u8] = b"lait.invitation.accept.v1";

/// A candidate's signed proof that it accepted an exact admission capability
/// under exact Coordinates (plan M2). It authorizes **no** operation except
/// redemption of that exact capability and candidate binding; the candidate
/// persists it and reuses it byte-for-byte on every retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationAcceptanceProof {
    pub version: u16,
    pub public_key: [u8; 32],
    pub accepted_at: u64,
    pub nonce: [u8; 16],
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

impl InvitationAcceptanceProof {
    /// The signature preimage: the accept domain followed by the canonical
    /// Coordinates digest, Space, approach Station, capability id, candidate
    /// actor/device, accepted-at, and nonce, fixed/length-prefixed.
    fn signing_preimage(
        &self,
        coordinates_digest: &[u8; 32],
        space: &[u8; SPACE_ID_LEN],
        approach_station: &[u8; 32],
        capability_id: &[u8; 32],
        candidate_actor: &str,
        candidate_device: &[u8; 32],
    ) -> Vec<u8> {
        let body = postcard::to_stdvec(&(
            self.version,
            coordinates_digest,
            space,
            approach_station,
            capability_id,
            candidate_actor,
            candidate_device,
            self.accepted_at,
            self.nonce,
        ))
        .expect("postcard acceptance preimage");
        length_framed(ACCEPT_DOMAIN, &body)
    }

    /// The acceptance id: BLAKE3 over the unsigned preimage (including time and
    /// nonce, excluding the signature).
    pub fn acceptance_id(
        &self,
        coordinates_digest: &[u8; 32],
        space: &[u8; SPACE_ID_LEN],
        approach_station: &[u8; 32],
        capability_id: &[u8; 32],
        candidate_actor: &str,
        candidate_device: &[u8; 32],
    ) -> [u8; 32] {
        blake3::derive_key(
            "lait.invitation-acceptance.v1",
            &self.signing_preimage(
                coordinates_digest,
                space,
                approach_station,
                capability_id,
                candidate_actor,
                candidate_device,
            ),
        )
    }

    /// Sign an acceptance proof from the candidate's device seed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        candidate_seed: &[u8; 32],
        accepted_at: u64,
        nonce: [u8; 16],
        coordinates_digest: &[u8; 32],
        space: &[u8; SPACE_ID_LEN],
        approach_station: &[u8; 32],
        capability_id: &[u8; 32],
        candidate_actor: &str,
    ) -> Option<Self> {
        let public_key = mechanics::crypto::device_from_seed(candidate_seed).key_bytes()?;
        let mut proof = Self {
            version: 1,
            public_key,
            accepted_at,
            nonce,
            signature: [0u8; 64],
        };
        let preimage = proof.signing_preimage(
            coordinates_digest,
            space,
            approach_station,
            capability_id,
            candidate_actor,
            &public_key,
        );
        proof.signature = mechanics::crypto::sign_detached(candidate_seed, &preimage);
        Some(proof)
    }

    /// Verify the proof binds this exact candidate/capability/Coordinates. The
    /// candidate device id must derive from `public_key`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        coordinates_digest: &[u8; 32],
        space: &[u8; SPACE_ID_LEN],
        approach_station: &[u8; 32],
        capability_id: &[u8; 32],
        candidate_actor: &str,
        candidate_device: &[u8; 32],
    ) -> bool {
        if self.version != 1 || &self.public_key != candidate_device {
            return false;
        }
        let preimage = self.signing_preimage(
            coordinates_digest,
            space,
            approach_station,
            capability_id,
            candidate_actor,
            candidate_device,
        );
        mechanics::crypto::verify_detached(&self.public_key, &preimage, &self.signature)
    }
}

impl SignedCoordinates {
    fn preimage(&self) -> Vec<u8> {
        let body = postcard::to_stdvec(&self.payload).expect("postcard coordinates payload");
        length_framed(COORDINATES_DOMAIN, &body)
    }

    /// Mint and sign Coordinates from the approach Station's device seed. The
    /// seed's public key must equal `payload.approach_station`.
    pub fn sign(payload: CoordinatesPayload, station_seed: &[u8; 32]) -> Self {
        let issuer = mechanics::crypto::device_from_seed(station_seed)
            .key_bytes()
            .expect("device key bytes");
        let mut coords = Self {
            version: 2,
            payload,
            issuer,
            signature_algorithm: SIG_ALG_ED25519,
            signature: [0u8; 64],
        };
        coords.signature = mechanics::crypto::sign_detached(station_seed, &coords.preimage());
        coords
    }

    /// The lowercase unpadded-base32 link body.
    pub fn render(&self) -> String {
        let mut s = data_encoding::BASE32_NOPAD.encode(&self.encode());
        s.make_ascii_lowercase();
        s
    }

    /// Parse a Coordinates link into canonical Coordinates. Accepts both the
    /// advertised `lait://join/<ticket>` form and the bare base32 ticket, and
    /// tolerates interior whitespace (terminal line-wrap in a copied link) —
    /// the base32 alphabet contains none, so stripping it is unambiguous.
    pub fn parse_link(link: &str) -> Result<Self, CoordinatesError> {
        let mut body = link.trim();
        for scheme in ["lait://join/", "lait://"] {
            if body.len() >= scheme.len() && body[..scheme.len()].eq_ignore_ascii_case(scheme) {
                body = &body[scheme.len()..];
                break;
            }
        }
        let compact: String = body
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let bytes = data_encoding::BASE32_NOPAD
            .decode(compact.as_bytes())
            .map_err(|_| CoordinatesError::BadLink)?;
        Self::decode_canonical(&bytes)
    }

    /// Canonical postcard bytes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard coordinates")
    }

    /// The canonical Coordinates digest an acceptance proof binds to.
    pub fn digest(&self) -> [u8; 32] {
        blake3::derive_key("lait.coordinates.v2", &self.encode())
    }

    /// Decode canonical bytes: size-bounded, exact decode/re-encode equality.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CoordinatesError> {
        if bytes.len() > MAX_DECODED {
            return Err(CoordinatesError::NonCanonical);
        }
        let coords: Self =
            postcard::from_bytes(bytes).map_err(|_| CoordinatesError::NonCanonical)?;
        if coords.encode() != bytes {
            return Err(CoordinatesError::NonCanonical);
        }
        Ok(coords)
    }

    /// Fully verify: version, algorithm, SpaceId shape, name hints, founding
    /// self-proof, issuer == approach_station, sorted/unique addresses, the
    /// outer signature, and the admission structure/signature.
    pub fn verify(&self) -> Result<VerifiedCoordinates, CoordinatesError> {
        if self.version != 2 {
            return Err(CoordinatesError::UnsupportedVersion(self.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(CoordinatesError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        let p = &self.payload;

        // SpaceId shape.
        let space = space_id_from_bytes(&p.space).ok_or(CoordinatesError::BadSpaceId)?;

        // Name hints: bounded + NFC.
        if p.display_name_hint.len() > MAX_NAME || !is_nfc(&p.display_name_hint) {
            return Err(CoordinatesError::BadNameHint);
        }
        if p.approach_nick_hint.len() > MAX_NICK || !is_nfc(&p.approach_nick_hint) {
            return Err(CoordinatesError::BadNameHint);
        }

        // Founding self-proof: the SpaceId must commit to the inception.
        if p.founder_inception.len() > MAX_INCEPTION {
            return Err(CoordinatesError::InceptionTooLarge);
        }
        let inception: SignedEvent = postcard::from_bytes(&p.founder_inception)
            .map_err(|_| CoordinatesError::FoundingInvalid)?;
        let founder_actor =
            mechanics::space::verify_founding(&space, &p.salt, &p.recovery_root, &inception)
                .map_err(|_| CoordinatesError::FoundingInvalid)?;

        // issuer == approach_station.
        if self.issuer != p.approach_station {
            return Err(CoordinatesError::IssuerMismatch);
        }

        // Routes: bounded, strictly increasing (sorted + unique), each a
        // usable direct address (no unspecified/multicast/broadcast/zero-port).
        if p.approach_routes.len() > MAX_ADDRS {
            return Err(CoordinatesError::BadAddresses);
        }
        for w in p.approach_routes.windows(2) {
            if w[0] >= w[1] {
                return Err(CoordinatesError::BadAddresses);
            }
        }
        if p.approach_routes.iter().any(|r| !r.is_usable()) {
            return Err(CoordinatesError::BadAddresses);
        }

        // Outer signature by the approach Station.
        if !mechanics::crypto::verify_detached(&self.issuer, &self.preimage(), &self.signature) {
            return Err(CoordinatesError::BadSignature);
        }

        // Admission structure/signature (authority/expiry checked at redemption).
        let admission = match &p.admission {
            CoordinatesAdmission::None => None,
            CoordinatesAdmission::Some(cap) => {
                cap.verify_structure(&space)?;
                Some((**cap).clone())
            }
        };

        Ok(VerifiedCoordinates {
            space,
            founder_actor,
            approach_station: DeviceId::from_key_bytes(&p.approach_station),
            display_name_hint: p.display_name_hint.clone(),
            approach_nick_hint: p.approach_nick_hint.clone(),
            approach_routes: p.approach_routes.iter().map(|a| a.to_socket()).collect(),
            admission,
        })
    }
}
