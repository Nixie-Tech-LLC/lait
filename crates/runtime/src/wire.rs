//! Shared canonical-wire helpers for signed runtime envelopes.

/// Build the length-framed signature preimage shared by every signed runtime
/// envelope: `u16be(domain_len) || domain || u32be(body_len) || body`. The
/// domain separates use-sites; the explicit lengths make the framing
/// unambiguous and canonical.
pub(crate) fn length_framed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + 4 + body.len());
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}
