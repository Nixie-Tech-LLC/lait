# Release integrity

This document describes the provenance guarantees attached to lait releases and
how consumers can verify them. It intentionally excludes credential enrollment
and private-key provisioning.

## Current status

| Control | Status | What it establishes |
|---|---|---|
| SHA-256 manifest | Published with releases | Downloaded files match the release manifest. |
| GitHub build-provenance attestation | Enabled for release archives | An archive was produced by the repository's release workflow. |
| GPG signatures for `sha256.sum` and `source.tar.gz` | Conditional on the release signing key being provisioned | The manifest or source archive was signed by the lait release key. |
| GPG-signed Git tag | Maintainer release procedure | The source tag was signed by the lait release key. |
| macOS Developer ID signing and notarization | Not enabled | No Apple platform-authenticity claim is currently made. |
| Windows Artifact Signing | Not enabled | No Windows publisher-signature claim is currently made. |

GitHub attestations establish provenance, not software safety. A valid
attestation links an artifact to a repository workflow and commit; it does not
prove that the source or build process is free of vulnerabilities.

## Download verification

Download an archive and `sha256.sum` from the same GitHub release. Verify the
manifest before running or installing the archive:

```sh
sha256sum -c sha256.sum
```

On macOS, use `shasum -a 256 -c sha256.sum` if GNU `sha256sum` is unavailable.
The manifest may cover files you did not download; a missing-file warning is not
an integrity failure for the files that were checked, but every file you intend
to install must report `OK`.

## Build-provenance verification

With a current GitHub CLI, verify the downloaded archive against this repository:

```sh
gh attestation verify ./lait-<target>.<archive> \
  --repo nixiesoftware/lait
```

Verification must identify `nixiesoftware/lait` as the source repository and the
expected release workflow. Do not weaken the repository constraint merely to
make an unexpected artifact pass.

## Source-signature verification

The public release key is [`lait-release-key.asc`](./lait-release-key.asc). Import
it only after comparing its fingerprint with a value published through an
independent trusted channel:

```sh
curl -fsSLo lait-release-key.asc \
  https://raw.githubusercontent.com/nixiesoftware/lait/main/docs/lait-release-key.asc
gpg --show-keys --fingerprint lait-release-key.asc
gpg --import lait-release-key.asc
```

When a release contains detached signatures, always provide both the signature
and signed file explicitly:

```sh
gpg --verify sha256.sum.asc sha256.sum
gpg --verify source.tar.gz.asc source.tar.gz
```

Then verify the archive checksums from the authenticated manifest. A valid
signature over `sha256.sum` authenticates the hashes recorded in that manifest;
it does not authenticate an unlisted file.

To verify a signed source tag in a clone:

```sh
git verify-tag vX.Y.Z
```

Confirm that Git reports the expected release key and that the tag resolves to
the commit advertised by the release.

## Missing signatures

Absence of a GPG signature is not equivalent to a bad signature. It means the
GPG provenance claim is unavailable and the consumer must decide whether GitHub
attestation plus the HTTPS release channel meets their policy.

A present but invalid signature, a signature by an unexpected key, a checksum
mismatch, or an attestation for a different repository or workflow is a hard
failure. Do not install the artifact.

The current signing workflow can skip GPG signing when its repository key is not
provisioned. Therefore consumers must check for signature assets rather than
assuming every release has them. Stable releases should move to fail-closed
signing once key provisioning is an enforced release prerequisite.

## Key management policy

- The public key is safe to distribute and is committed to this repository.
- The certification key and revocation material remain offline.
- CI receives only a dedicated release-signing subkey through repository secret
  storage.
- Private keys, certificate bundles, passphrases, API keys, tenant identifiers,
  and signing-account credentials must never be committed.
- Rotation publishes the updated public key before a release uses the new
  subkey. Revocation is announced through the repository and release channels.
- A compromised signing credential stops releases until it is revoked, replaced,
  and the affected release set is identified.

## Maintainer release policy

1. Build only from an reviewed release commit and immutable version tag.
2. Keep third-party actions pinned to immutable revisions.
3. Give build jobs the minimum permissions required for checkout, attestation,
   and upload.
4. Sign before archiving when platform signing is enabled so distributed
   archives contain the signed executable.
5. Verify signatures and attestations before publishing release notes or package
   manager metadata.
6. Never print, upload as an artifact, or interpolate credential values into
   command lines that may be logged.
7. Treat an unsigned stable release as an explicit exception until the pipeline
   enforces fail-closed signing.

Credential provisioning and platform-account enrollment are maintained outside
the public repository. Workflow comments mark the macOS and Windows insertion
points without containing credentials.
