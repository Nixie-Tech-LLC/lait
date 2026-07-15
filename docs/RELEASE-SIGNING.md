# Release signing & the custom-build architecture

This document is the design + runbook for lait's signed release pipeline. It is
also intended as a **reusable template** for other Nixie projects (e.g. warren).

## Why lait doesn't use cargo-dist's built-in signing

cargo-dist (v0.32.0, the current release) cannot produce the artifacts we need:

- **macOS notarization is impossible with the built-in signer.** Its `macos-sign`
  runs a plain `codesign` with **no hardened runtime** (issue #1534, open since
  2024). A signature without hardened runtime *fails* Apple notarization, so its
  output can never be notarized or stapled.
- **Windows signing is SSL.com-only.** cargo-dist has no backend for **Azure
  Artifact Signing** (issue #1122/#2395), which is the CA we chose (~$120/yr vs
  ~$1,200/yr for SSL.com eSigner).
- **There is no post-build-pre-archive hook.** `github-build-setup` runs *before*
  `dist build`, and `dist build` compiles + archives atomically. There is nowhere
  to inject "sign the binary after compile, before it is tar/zipped."

To sign the **distributed** archives (the exact `.tar.gz`/`.zip` that
brew/scoop/winget/`curl|sh` hand out), the binary must be signed before
archiving. That requires owning the build.

## The architecture (the uv/ruff pattern)

Set in `dist-workspace.toml`:

```toml
build-local-artifacts = false
local-artifacts-jobs  = ["./build-binaries"]
```

cargo-dist then **replaces** its default per-target build job with a call to our
reusable workflow `.github/workflows/build-binaries.yml` (`on: workflow_call`),
passing the release `plan` as a string input. cargo-dist still owns everything
else: the `plan`, the installers, the unified `sha256.sum`, GitHub Release
creation, and the publisher fan-out.

### The contract build-binaries.yml MUST satisfy

Per target, build the binary, **sign it**, then hand-roll the archive in the
exact shape cargo-dist's plan advertises, and upload it under an `artifacts-*`
name. cargo-dist's `host` job collects everything matching `artifacts-*` by
**filename** — so the filenames and in-archive layout are the contract:

| Requirement | Value |
|---|---|
| Unix archive name | `lait-<target-triple>.tar.gz` (+ `.tar.gz.sha256`) |
| Windows archive name | `lait-<target-triple>.zip` (+ `.zip.sha256`) |
| In-archive layout (unix) | `lait-<target>/` containing `lait`, `CHANGELOG.md`, `LICENSE-APACHE`, `LICENSE-MIT`, `README.md` |
| In-archive layout (windows) | flat: `lait.exe` + the 4 misc files at the zip root |
| Upload artifact name | `artifacts-<target>` (matches the host job's `artifacts-*` glob) |

The nested-on-unix / flat-on-windows split is the same layout the self-updater
(`update_bin_path_in_archive`) and the `binstall` metadata encode. Keep all three
in lockstep.

The misc files matter: lait does **not** set `auto-includes = false`, so the plan
lists `CHANGELOG.md`, `LICENSE-APACHE`, `LICENSE-MIT`, `README.md` inside each
archive. The hand-rolled archive must include them to match.

### Signing insertion points

- **macOS** (`macos-14`/`macos-15` runner, per target):
  1. `cargo build --release --locked --target <t>`
  2. `codesign --force --options runtime --timestamp -s "$DEVELOPER_ID" target/<t>/release/lait`
  3. Build the archive (binary + misc, nested).
  4. Build a `.pkg` wrapping the signed binary (`pkgbuild`), notarize it
     (`xcrun notarytool submit --wait`), and `xcrun stapler staple` it — a bare
     Mach-O can't be stapled, the `.pkg` can. Upload the stapled `.pkg` as an
     **additional** asset `lait-<target>.pkg` for the offline-clean GUI path; the
     tarball binary shares the notarized cdhash so Gatekeeper's online lookup also
     clears it.
- **Windows** (`windows-latest`, x86_64):
  1. `cargo build --release --locked --target x86_64-pc-windows-msvc`
  2. Azure-sign the `.exe` **before** zipping, via
     `azure/artifact-signing-action` (OIDC to Azure; no stored cert).
  3. `7z a lait-<target>.zip lait.exe <misc>` + `sha256sum`.
- **Linux** (no OS signing): build + archive. Provenance attestation covers it.

### Attestation

Because the default job's `actions/attest` step is gone, add an attestation step
to each build-binaries job (after archiving, `subject-path` = the archive), or a
single global attest over all archives. Requires `id-token: write` +
`attestations: write` job permissions (set via `github-custom-job-permissions`).

## Secret-gating (so main stays releasable before accounts exist)

Every signing step is gated on its secret being present and **soft-skips** when
absent — the same pattern as `publish-homebrew/scoop/winget`. A release cut
before the certs land produces **unsigned** archives (still valid, still
installable); the first release after the secrets are added is signed. The custom
job also runs on `pull_request` (build-only, no signing) so the build path is
CI-tested without a tag.

### Required repository secrets

Add these under **Settings → Secrets and variables → Actions** once the account
setup below produces them. All certs must be issued to the legal entity **Nixie
Solutions LLC** (distinct from the `Nixie-Tech-LLC` GitHub org slug).

| Secret | For | Source |
|---|---|---|
| `APPLE_TEAM_ID` | 10-char Apple Team ID | Apple Developer (after enrollment) |
| `APPLE_DEVELOPER_ID` | codesign identity, e.g. `Developer ID Application: Nixie Solutions LLC (TEAMID)` | Apple Developer |
| `APPLE_CERT_P12` / `APPLE_CERT_PASSWORD` | base64 of the **Developer ID Application** cert+key `.p12`, and its password | Apple Developer + you |
| `APPLE_INSTALLER_ID` | pkg-signing identity, e.g. `Developer ID Installer: Nixie Solutions LLC (TEAMID)` | Apple Developer |
| `APPLE_INSTALLER_P12` / `APPLE_INSTALLER_PASSWORD` | base64 of the **Developer ID Installer** cert+key `.p12`, and its password | Apple Developer + you |
| `APPLE_NOTARY_KEY` / `APPLE_NOTARY_KEY_ID` / `APPLE_NOTARY_ISSUER` | base64 of the App Store Connect API `.p8`, its Key ID, and the Issuer ID (for `notarytool`) | App Store Connect |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_SUBSCRIPTION_ID` | OIDC login (federated, no stored cert) | Azure / Entra ID |
| `AZURE_SIGNING_ENDPOINT` | region endpoint, e.g. `https://wus2.codesigning.azure.net` | Azure |
| `AZURE_SIGNING_ACCOUNT` / `AZURE_SIGNING_PROFILE` | the Artifact Signing account name + certificate profile name | Azure |
| `GPG_SIGNING_KEY` | base64 of the exported **release signing subkey** (private) | your offline keyring (§C) |
| `GPG_SIGNING_KEY_ID` | fingerprint of that signing subkey | `gpg --list-secret-keys` |
| `GPG_PASSPHRASE` | passphrase for the subkey (omit if none) | you |

## Account setup runbook (what you do)

### A. Apple / macOS — start this first (the long pole)

The D-U-N-S request + org enrollment can take several business days, so kick it
off before anything else.

1. **Get a D-U-N-S number** for the exact legal name **Nixie Solutions LLC**.
   Use Apple's lookup at <https://developer.apple.com/enroll/duns-lookup/> — it
   requests one from Dun & Bradstreet for free if you don't have one. (Up to
   ~5 business days.)
2. **Enroll in the Apple Developer Program as an *Organization*** ($99/yr,
   <https://developer.apple.com/enroll/>). Needs the D-U-N-S, the legal name, and
   your authority to bind the company. When approved you get a **Team ID**
   (10 chars) → `APPLE_TEAM_ID`.
3. **Create two certificates.** Generate one CSR and reuse it for both:
   ```sh
   openssl req -newkey rsa:2048 -nodes \
     -keyout lait-signing.key -out lait-signing.csr \
     -subj "/CN=Nixie Solutions LLC/C=US"
   ```
   At <https://developer.apple.com/account/resources/certificates> → **+**:
   - **Developer ID Application** (signs the `lait` binary) — upload the CSR,
     download the `.cer`.
   - **Developer ID Installer** (signs the `.pkg`) — upload the same CSR,
     download the `.cer`.
   Bundle each `.cer` with the private key into a password-protected `.p12`:
   ```sh
   # repeat for the installer cert
   openssl x509 -in developerID_application.cer -inform DER -out app.pem
   openssl pkcs12 -export -out app.p12 -inkey lait-signing.key -in app.pem
   ```
   The identity strings (`security find-identity -v -p codesigning` once imported,
   or from the portal) are `Developer ID Application: Nixie Solutions LLC (TEAMID)`
   → `APPLE_DEVELOPER_ID`, and the Installer equivalent → `APPLE_INSTALLER_ID`.
4. **Create an App Store Connect API key** for notarization: App Store Connect →
   **Users and Access → Integrations → App Store Connect API → Team Keys → +**,
   role **Developer**. Download the `.p8` **once** (it's unrecoverable). Record
   the **Key ID** and the page's **Issuer ID**.
5. **Base64 the binaries** for the secrets:
   ```sh
   base64 -i app.p12       | pbcopy   # → APPLE_CERT_P12
   base64 -i installer.p12 | pbcopy   # → APPLE_INSTALLER_P12
   base64 -i AuthKey_XXXX.p8 | pbcopy # → APPLE_NOTARY_KEY
   ```
   Add those plus `APPLE_CERT_PASSWORD`, `APPLE_INSTALLER_PASSWORD`,
   `APPLE_DEVELOPER_ID`, `APPLE_INSTALLER_ID`, `APPLE_NOTARY_KEY_ID`,
   `APPLE_NOTARY_ISSUER`, `APPLE_TEAM_ID`.

### B. Azure / Windows — Artifact Signing

1. **A *paid* Azure subscription** — free/trial/sponsored subs are not eligible
   for signing. Record the **Subscription ID**.
2. **Create an Artifact Signing account** (portal → search "Trusted Signing" /
   "Artifact Signing" → Create). SKU **Basic** (~$9.99/mo, 5 000 signatures).
   Choose a US region + resource group. Note the **account name** and the
   **region endpoint** (e.g. `https://wus2.codesigning.azure.net`).
3. **Validate identity** for **Nixie Solutions LLC** (account → Identity
   validations → new *Organization* validation: legal name, address, etc.).
   ⚠️ Org validation for a young LLC can trip CA/Browser young-entity checks; if
   it stalls, the **US individual** validation path is the confirmed fallback
   (the cert then issues under your name rather than the LLC). Allow a few days.
4. **Create a Certificate Profile** of type **Public Trust** once validated →
   `AZURE_SIGNING_PROFILE`.
5. **Wire OIDC** so Actions signs with no stored cert:
   - Create an **Entra ID app registration** (or a user-assigned managed
     identity). Note **Tenant ID** and **Client ID**.
   - On it, add a **federated credential** for GitHub with subject
     `repo:Nixie-Tech-LLC/lait:ref:refs/tags/*` (restrict to tag releases; add an
     environment-scoped one too if you gate releases on an environment).
   - Grant that identity the **Trusted Signing Certificate Profile Signer** role
     on the signing account (account → Access control (IAM) → Add role
     assignment).
6. **Add secrets**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_SUBSCRIPTION_ID`,
   `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE`.

### C. GPG release key — source provenance for redistributors

This is **separate** from the OS code signing above. It lets a downstream
provider (a distro packager, Homebrew, Nix, …) verify lait's source is
authentically ours and build + ship their *own* binary — so their users aren't
locked into the Nixie-built artifacts. It's the model core git uses: upstream
signs the source, distributors build from it.

Use a **master key kept offline** and a **signing subkey** in CI, so a leaked CI
secret is revocable without losing the identity.

The key's identity (UID) is a freeform brand string — we use **Nixie Software** —
and is deliberately independent of the legal entity ("Nixie Solutions LLC") that
the Apple/Azure code-signing certs require. A GPG UID vouches for source
provenance, not a legal signer.

1. **Generate the key** (do this on a trusted machine, once):
   ```sh
   gpg --quick-generate-key "Nixie Software (lait release signing) <releases@…>" ed25519 sign 2y
   FPR=<the printed fingerprint>
   # a dedicated signing SUBKEY with its own 1-year expiry:
   gpg --quick-add-key "$FPR" ed25519 sign 1y
   ```
2. **Export the public key** into the repo so verifiers have it:
   ```sh
   gpg --armor --export "$FPR" > docs/lait-release-key.asc   # commit this
   ```
   Optionally publish it to keyservers (`gpg --send-keys "$FPR"`).
3. **Export only the SIGNING SUBKEY's private half** for CI (note the trailing
   `!` — it exports just that subkey, not the master):
   ```sh
   SUBFPR=<the subkey fingerprint from `gpg --list-secret-keys --with-subkey-fingerprints`>
   gpg --armor --export-secret-subkeys "${SUBFPR}!" | base64 | pbcopy   # → GPG_SIGNING_KEY
   ```
   Add `GPG_SIGNING_KEY`, `GPG_SIGNING_KEY_ID` (= `$SUBFPR`), and `GPG_PASSPHRASE`
   (if you set one) as repo secrets. **Keep the master key + its revocation
   certificate offline** (a hardware token or an encrypted backup).
4. **Sign release tags going forward.** Configure once, then `git tag -s`:
   ```sh
   git config user.signingkey "$FPR"
   git tag -s vX.Y.Z -m "lait vX.Y.Z"      # instead of `git tag vX.Y.Z`
   ```
   The existing release ritual (bump `Cargo.toml` + `CHANGELOG`, push the tag)
   is unchanged except the tag is now `-s`.

**Rotation:** when the subkey nears expiry, `gpg --quick-add-key` a new one, swap
`GPG_SIGNING_KEY`/`GPG_SIGNING_KEY_ID`, re-export the public key. The master —
and thus the published trust anchor — never changes.

## What the CI will do (what I wire once the secrets exist)

Each step is gated on `secrets.<X> != ''` and soft-skips when absent. Shapes:

**macOS** — inserted between *Build* and *Archive* in the `macos` job, so the
tarball ships the signed binary; the `.pkg` is an additional stapled asset:
```yaml
- name: Import signing certs           # temp keychain from APPLE_CERT_P12 / APPLE_INSTALLER_P12
- name: Codesign (hardened runtime)    # codesign --options runtime --timestamp -s "$APPLE_DEVELOPER_ID" lait
#   (Archive step runs here → tarball now holds the signed binary)
- name: Notarize the binary            # ditto -c -k lait notarize.zip; xcrun notarytool submit --wait (App Store Connect key)
- name: Build + notarize + staple .pkg # pkgbuild --sign "$APPLE_INSTALLER_ID" …; notarytool submit --wait; xcrun stapler staple lait-<target>.pkg
- name: Upload .pkg                     # extra release asset (bare Mach-O can't be stapled; the pkg can)
```
**Windows** — between *Build* and *Archive* in the `windows` job, so the zipped
`lait.exe` is signed:
```yaml
- uses: azure/login@v2                  # OIDC via AZURE_* — no stored cert
- uses: azure/trusted-signing-action@v0 # signs target\…\lait.exe against AZURE_SIGNING_ACCOUNT/PROFILE
#   (Archive step zips the now-signed exe)
```
**Linux** — no OS signing; the build-provenance attestation (already wired)
covers it.

**Source (GPG)** — already wired, `.github/workflows/publish-signatures.yml`
(decoupled, `workflow_run`, soft-skips until `GPG_SIGNING_KEY` exists). It
GPG-signs `sha256.sum` and `source.tar.gz` and attaches `.asc` sidecars. Since
`sha256.sum` covers every artifact, one verified signature transitively vouches
for all of them.

## Verifying lait's source (for redistributors)

A packager verifies provenance without trusting our binaries at all:

```sh
# one-time: import the release key
curl -sSL https://raw.githubusercontent.com/Nixie-Tech-LLC/lait/main/docs/lait-release-key.asc | gpg --import

# verify a release you downloaded
gpg --verify sha256.sum.asc sha256.sum        # the manifest is ours
sha256sum -c sha256.sum                         # the artifacts match it
# and/or verify the tag directly in a clone:
git verify-tag vX.Y.Z
```

Then build from the verified `source.tar.gz` (or the tag) and package however you
like — the GPG chain is independent of the Apple/Azure code signing on our own
binaries.

## Verification strategy (given it can't run locally)

1. `dist plan` / `dist generate` must stay consistent (CI's `release-dry-run`
   enforces this on every PR).
2. The `pull_request` trigger builds every target **without** signing, proving
   the build + hand-rolled archive path on real runners.
3. First **real** signed release is a `dev`-channel or `-rc` tag, verified with
   `gh attestation verify`, `codesign -dv --verbose=4`, `spctl -a -vvv -t install`
   (pkg), and `Get-AuthenticodeSignature` (Windows) before a stable tag.

## Migration steps (incremental, each independently valid)

1. ✅ **Done** (`b3bc929`). Flip `build-local-artifacts = false` +
   `local-artifacts-jobs`, add a build-binaries.yml that reproduces today's
   **unsigned** archives exactly (Linux/macOS/Windows), regenerate `release.yml`,
   confirm `dist plan` matches. Releases work, unsigned, on the new architecture.
2. ✅ **Done** (`b3bc929`). Attestation runs inside the custom job (skipped on PR
   test-builds).
3. ✅ **Done + wired.** GPG source signing (`publish-signatures.yml`), identity
   **Nixie Software**. Soft-skips until `GPG_SIGNING_KEY` is provisioned (§C).
4. ⏸️ **On hold (deferred by decision).** macOS codesign + notarize + `.pkg`.
   The Apple account setup (§A) and the CI steps are documented but NOT being
   wired yet. The `SIGNING SLOT` comment in `build-binaries.yml` marks where.
5. ⏸️ **On hold (deferred by decision).** Windows Azure signing (§B). Same — the
   marked slot is a comment only; nothing is half-wired.
6. When resumed: flip the first signed `-rc` release, run the verification
   checklist, then a stable tag.

### Who does what next

- **You (now):** do §C (GPG — quick, fully local, no accounts): generate the
  key, commit `docs/lait-release-key.asc`, add the `GPG_*` secrets, and start
  signing tags with `git tag -s`. That fully activates source provenance.
- **Deferred:** the Apple (§A) and Windows/Azure (§B) binary signing are on hold
  by decision. When you want them, do the account setup and ping me to wire the
  steps at the `SIGNING SLOT` markers, then verify on an `-rc` tag.
