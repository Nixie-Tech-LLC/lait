# Installing lait

`lait` is a single self-contained binary that runs on **Linux, macOS, and
Windows** (arm64 + x86_64). Pick whichever channel fits your platform — they all
land the same `lait` executable. Upgrade any install in place with `lait update`
(a native self-updater), regardless of how you installed it.

> **Heads-up on the crypto:** lait's end-to-end encryption is research-grade and
> **not yet independently audited** — don't trust it with sensitive data yet. See
> [`docs/HARDENING.md`](HARDENING.md).

## Quick pick

| You have… | Use |
|---|---|
| macOS / Linux, want one command | the shell installer |
| Windows | the PowerShell installer, Scoop, or winget |
| Homebrew | `brew install nixie-tech-llc/tap/lait` |
| Rust toolchain, want a prebuilt binary | `cargo binstall lait` |
| Rust toolchain, want to build | `cargo install lait` |
| Running an always-on seed | Docker |

## Shell installer (macOS / Linux)

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.sh | sh
```

Places `lait` in `~/.cargo/bin` (on `PATH` for most setups).

## PowerShell installer (Windows)

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex"
```

## Homebrew (macOS / Linux)

```sh
brew install nixie-tech-llc/tap/lait
```

## Scoop (Windows)

```powershell
scoop bucket add lait https://github.com/Nixie-Tech-LLC/scoop-bucket
scoop install lait
```

## winget (Windows)

```powershell
winget install NixieTechLLC.Lait
```

## cargo-binstall (prebuilt, no compile)

Fetches the prebuilt release archive instead of building from source:

```sh
cargo binstall lait
```

## cargo install (from source)

```sh
cargo install lait --locked
```

Requires **Rust 1.91+** (the floor is driven by iroh 1.0.0-rc.1).

## From a git checkout

```sh
git clone https://github.com/Nixie-Tech-LLC/lait
cd lait
cargo build --release   # → target/release/lait
```

## Docker — always-on seed node

A seed is a headless peer that stays reachable to bootstrap and backfill
encrypted workspace history for other nodes. It holds only ciphertext until an
admin admits it.

```sh
docker compose up -d --build          # from the repo root
docker compose exec seed lait id      # copy the node id
# from an admin node:  lait members add <that-id>
docker compose exec seed lait seed add <room-ticket>   # adopt a workspace to serve
```

See [`docker-compose.yml`](../docker-compose.yml) for details. iroh handles NAT
traversal via relays, so no inbound port is required (publishing a UDP port just
speeds up direct dials).

## Verifying a download

Every release archive ships a `.sha256` sidecar, and the release page lists a
unified `sha256.sum`. To check a manual download:

```sh
sha256sum -c lait-x86_64-unknown-linux-gnu.tar.gz.sha256
```

## Shell completions & man page

lait generates both at runtime from its own command tree:

```sh
lait completions bash > ~/.local/share/bash-completion/completions/lait
lait completions zsh  > "${fpath[1]}/_lait"
lait completions fish > ~/.config/fish/completions/lait.fish
lait completions powershell | Out-String | Invoke-Expression   # current session
lait man > lait.1     # roff man page
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

## After installing

```sh
lait projects new "Engineering" --key ENG
lait new "fix login race" -p ENG -P high
lait tui
```

Register the MCP server with an AI agent in one step:

```sh
lait install-mcp --client claude    # or: cursor | windsurf | generic
```
