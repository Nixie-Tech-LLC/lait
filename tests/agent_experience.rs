//! The Agent Experience, end to end (Architecture B): a user sponsors a
//! co-located agent **once**, then the agent acts as **itself** — its work
//! signed and attributed to its own identity, distinct from the human's, in
//! **one store** (one home, one daemon). No second store copy, no restart.
//!
//! This is the automated form of the recorded live acceptance. It drives the
//! real binary over the real control socket, so it exercises the whole stack:
//! provisioning (self-inception + sponsorship into the shared store), the
//! contributor-capability grant, the `act_as` selector, per-identity Session
//! docking, and signed attribution.

use std::process::Command;

/// Clean-env entrypoint: a developer's shell `$LAIT_HOME` (their live node) must
/// never leak into a test that spawns a daemon for a temp home.
#[ctor::ctor]
fn scrub_ambient_lait_env() {
    for key in ["LAIT_HOME", "LAIT_STORE", "LAIT_CONFIG_ROOT"] {
        std::env::remove_var(key);
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

fn tmp_home(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("gc-axe-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `lait --home <home> …`, optionally acting as a local agent (`LAIT_AS`).
/// `LAIT_IDLE_SECS=0` so an auto-spawned daemon never lingers between calls.
fn lait(
    home: &std::path::Path,
    cfg: &std::path::Path,
    act_as: Option<&str>,
    args: &[&str],
) -> String {
    let mut cmd = Command::new(bin());
    cmd.env("LAIT_CONFIG_ROOT", cfg)
        .env("LAIT_IDLE_SECS", "0")
        .arg("--home")
        .arg(home)
        .args(args);
    if let Some(a) = act_as {
        cmd.env("LAIT_AS", a);
    }
    let out = cmd.output().expect("spawn lait");
    // Return stdout; the callers assert on it. stderr is surfaced on failure.
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() && stdout.is_empty() {
        return format!("ERR: {}", String::from_utf8_lossy(&out.stderr));
    }
    stdout
}

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s.trim()).unwrap_or_else(|e| panic!("not JSON ({e}): {s:?}"))
}

#[test]
fn a_sponsored_agent_acts_as_itself_in_one_store() {
    let home = tmp_home("solo");
    let cfg = home.join("cfg");

    // The human founds the space and files the first issue (which creates the
    // default project PROJ).
    let init = lait(
        &home,
        &cfg,
        None,
        &["init", "--name", "PROJ", "--nick", "Huginn"],
    );
    assert!(!init.starts_with("ERR:"), "init failed: {init}");
    lait(&home, &cfg, None, &["new", "human-filed issue"]);

    let human = json(&lait(&home, &cfg, None, &["--json", "whoami"]));
    let human_actor = human["actor"].as_str().unwrap().to_string();
    let human_device = human["device"].as_str().unwrap().to_string();

    // Sponsor a co-located agent in ONE step.
    let prov = lait(&home, &cfg, None, &["members", "agent", "--new", "scout"]);
    assert!(prov.contains("provisioned"), "provision failed: {prov}");

    // whoami AS the agent: a DISTINCT identity, a member with write standing,
    // the scoped read/contributor capabilities, and a sponsor link.
    let agent = json(&lait(&home, &cfg, Some("scout"), &["--json", "whoami"]));
    let agent_actor = agent["actor"].as_str().unwrap().to_string();
    let agent_device = agent["device"].as_str().unwrap().to_string();
    assert_ne!(
        agent_actor, human_actor,
        "the agent must have its OWN actor"
    );
    assert_ne!(
        agent_device, human_device,
        "the agent must sign with its OWN device"
    );
    assert_eq!(
        agent["can_write"],
        serde_json::json!(true),
        "a sponsored member writes"
    );
    assert!(
        agent["did"]
            .as_str()
            .unwrap_or_default()
            .starts_with("did:key:z6Mk"),
        "the agent exposes a did:key: {}",
        agent["did"]
    );
    assert_eq!(
        agent["sponsor"].as_str(),
        Some(human_actor.as_str()),
        "the roster renders the sponsor relationship"
    );
    let caps: Vec<String> = agent["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(
        caps.contains(&"space.issue.read".to_string())
            && caps.contains(&"space.contributor".to_string()),
        "a sponsored member gets the contributor scoped caps (read+write), got {caps:?}"
    );
    // But NEVER membership authority.
    assert!(
        !caps.contains(&"space.admin".to_string()),
        "an agent is not an admin"
    );

    // The agent files an issue AS ITSELF — proving it can both read the catalog
    // (scoped read) and author (write standing) in the one shared store.
    let filed = lait(
        &home,
        &cfg,
        Some("scout"),
        &["new", "agent-filed issue", "-p", "PROJ"],
    );
    assert!(
        !filed.starts_with("ERR:") && filed.to_uppercase().contains("PROJ-"),
        "the agent must be able to file an issue as itself: {filed}"
    );

    // The roster shows both members in the ONE store, the agent sponsored.
    let members = json(&lait(&home, &cfg, None, &["--json", "members"]));
    let rows = members["members"].as_array().cloned().unwrap_or_default();
    let agent_row = rows
        .iter()
        .find(|m| m["key"].as_str() == Some(&agent_actor))
        .expect("the agent is a member in the same store");
    assert_eq!(agent_row["sponsor"].as_str(), Some(human_actor.as_str()));
    assert!(rows
        .iter()
        .any(|m| m["key"].as_str() == Some(&human_actor) && m["role"] == "admin"));

    std::fs::remove_dir_all(&home).ok();
}
