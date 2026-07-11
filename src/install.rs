//! `groupchat install-mcp`: register the MCP server with an agent's config in
//! one explicit step, instead of hand-editing JSON. Merges into the target
//! client's `mcpServers` block without clobbering other servers.

use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Map, Value};

/// MCP-speaking agent whose config we know how to write.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Client {
    /// Claude Code (`.mcp.json` project, `~/.claude.json` user).
    Claude,
    /// Cursor (`.cursor/mcp.json`).
    Cursor,
    /// Windsurf (`~/.codeium/windsurf/mcp_config.json`, global only).
    Windsurf,
    /// Any client that reads a `.mcp.json` in the working directory.
    Generic,
}

/// Where to write the config: shared across a machine, or local to a project.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Scope {
    User,
    Project,
}

fn home() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .ok_or_else(|| anyhow!("could not determine home directory"))
}

/// Sensible default scope per client (Windsurf only has a global config).
fn default_scope(client: Client) -> Scope {
    match client {
        Client::Windsurf => Scope::User,
        _ => Scope::Project,
    }
}

/// Resolve the config file for a client + scope.
fn config_path(client: Client, scope: Scope) -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("get current dir")?;
    Ok(match (client, scope) {
        (Client::Generic, _) | (Client::Claude, Scope::Project) => cwd.join(".mcp.json"),
        (Client::Claude, Scope::User) => home()?.join(".claude.json"),
        (Client::Cursor, Scope::Project) => cwd.join(".cursor").join("mcp.json"),
        (Client::Cursor, Scope::User) => home()?.join(".cursor").join("mcp.json"),
        (Client::Windsurf, _) => home()?
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    })
}

/// Build the `mcpServers` entry for this binary: an absolute path so it runs
/// even when `groupchat` isn't on PATH, carrying GROUPCHAT_HOME if it's set.
fn server_entry() -> Result<Value> {
    let exe = std::env::current_exe().context("locate groupchat binary")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let mut entry = Map::new();
    entry.insert("command".into(), json!(exe.to_string_lossy()));
    entry.insert("args".into(), json!(["mcp"]));
    if let Some(h) = std::env::var_os("GROUPCHAT_HOME") {
        entry.insert(
            "env".into(),
            json!({ "GROUPCHAT_HOME": h.to_string_lossy() }),
        );
    }
    Ok(Value::Object(entry))
}

/// Register (or update) the groupchat MCP server in `client`'s config. With
/// `print`, returns the would-be file contents instead of writing.
pub fn install_mcp(
    client: Client,
    scope: Option<Scope>,
    name: &str,
    print: bool,
) -> Result<String> {
    let scope = scope.unwrap_or_else(|| default_scope(client));
    let path = config_path(client, scope)?;

    let mut root: Value = if path.exists() {
        let data = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if data.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?
        }
    } else {
        json!({})
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} is not a JSON object", path.display()))?;
    let servers = obj.entry("mcpServers").or_insert_with(|| json!({}));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers in {} is not an object", path.display()))?;
    let existed = servers.contains_key(name);
    servers.insert(name.to_string(), server_entry()?);

    let pretty = serde_json::to_string_pretty(&root)? + "\n";
    if print {
        return Ok(pretty);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, &pretty).with_context(|| format!("write {}", path.display()))?;
    Ok(format!(
        "{} MCP server '{}' in {}\nRestart your agent (or reload its MCP servers) to pick it up.",
        if existed { "updated" } else { "added" },
        name,
        path.display()
    ))
}
