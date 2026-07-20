# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability-reporting feature for this repository. Include affected
versions, impact, reproduction steps or a proof of concept, and any suggested
mitigation.

Do not include real user data, private keys, recovery material, or credentials in
a report. Test with disposable spaces and keys.

## Scope

Security-sensitive areas include actor identity, membership replay, encryption
and key epochs, invites, recovery and custody, local secret storage, network
framing, the daemon control channel, and the loopback web surface.

The current security assumptions and known non-goals are documented in
[`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md). Novel cryptographic protocol
code is not represented as independently audited.

## Supported versions

Security fixes target the current release line and the current `main` branch.
Older pre-1.0 formats may require reinitializing or rejoining rather than an
in-place compatibility migration. A report should identify the exact lait
version and store schema when possible.
