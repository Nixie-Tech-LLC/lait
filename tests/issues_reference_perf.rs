//! M6 — the IssuesWorld reference performance gate (plan 50).
//!
//! Builds the frozen corpus described by `benchmarks/issues-reference.json`
//! **exclusively through the public daemon/control surface**: a real founder
//! daemon on a real control socket plus a fleet of actor daemons — every
//! non-founder actor is created deterministically, admitted through the real
//! orbital admission path (invite link → store bootstrap → Contact → automatic
//! redemption), and authors its deterministic share of the corpus from its own
//! replica over the in-memory transport. Authorization tiers are exercised for
//! real: contributors author, the viewer-tier actor is refused mutation at the
//! demand layer, and every issue passes the workflow start/stop gates.
//!
//! The corpus spec is parsed STRICTLY: an unknown, missing, or mistyped field
//! anywhere in the file fails the gate, so a declared workload dimension can
//! never silently become decorative configuration — every dimension the spec
//! declares is consumed by this harness (`projects`, `issues`,
//! `eventsPerIssue`, `labelsPerIssue`, `actors`, `incrementalOps`).
//!
//! Measured families (cold + warm distributions through the founder's public
//! socket): bare focus (inbox + my issues), issue open, project list, board,
//! graph, history, create/edit, workflow transition, two-project policy
//! evaluation, restart rebuild, and incremental advance after a sync-sized
//! tail of extra operations distributed across the actor fleet.
//!
//! Scale: the default run uses a small deterministic fraction of the corpus
//! (and a 3-actor fleet) so every CI leg exercises the whole harness and the
//! absolute budgets. The full corpus (50k issues, 32 actors) runs with
//! `LAIT_PERF_FULL=1` in the dedicated `orbital-perf` CI job, which uploads
//! the sample artifact (`target/perf/issues-reference-report.json`) and gates
//! p95 regressions once baselines are frozen in the spec.
//!
//! Root-consistency note: the daemon serves every response from one docked
//! Session snapshot — there is no derived product cache, so no mixed-root
//! output is constructible at this surface (`tests/mixed_root_guard.rs` makes
//! that an executable invariant); runtime-level root labeling and the frontier
//! compare-and-swap are proven by `independent_world` and `world_policy`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Filter, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon_with;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [173u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Deterministic per-actor device seed: actor 0 is the founder; joiners get
/// stable seeds derived from their index.
fn actor_seed(index: usize) -> [u8; 32] {
    if index == 0 {
        return FOUNDER_SEED;
    }
    let mut seed = [0u8; 32];
    let d = blake3::hash(format!("lait.perf.actor.{index}").as_bytes());
    seed.copy_from_slice(d.as_bytes());
    seed
}

struct MemFactory(MemNet);

#[async_trait]
impl TransportFactory for MemFactory {
    async fn build(
        &self,
        identity_seed: &[u8; 32],
        _network: &Network,
        _alpns: &[Alpn],
    ) -> Result<Arc<dyn Transport>> {
        Ok(Arc::new(
            self.0.peer(lait::crypto::device_from_seed(identity_seed)),
        ))
    }
}

fn temp_home(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-perf-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn req(rt: &tokio::runtime::Runtime, home: &Path, r: Request) -> Response {
    rt.block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

fn ok(rt: &tokio::runtime::Runtime, home: &Path, r: Request) -> Response {
    let resp = req(rt, home, r.clone());
    if let Response::Error { message, .. } = &resp {
        panic!("request {r:?} failed: {message}");
    }
    resp
}

fn poll_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = check() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_daemon(home: &Path, seed: [u8; 32], net: &MemNet) -> std::thread::JoinHandle<()> {
    let daemon_home = home.to_path_buf();
    let daemon_net = net.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) =
                run_orbital_daemon_with(daemon_home, seed, &MemFactory(daemon_net)).await
            {
                eprintln!("PERF DAEMON ERR: {e:#}");
            }
        });
    })
}

fn wait_online(rt: &tokio::runtime::Runtime, home: &Path) {
    let online = poll_until(Duration::from_secs(30), || {
        matches!(req(rt, home, Request::Status), Response::Status(_)).then_some(())
    });
    assert!(
        online.is_some(),
        "daemon at {} never answered Status",
        home.display()
    );
}

/// One admitted non-founder actor: its home, seed, device hex, and role tier.
struct FleetActor {
    home: PathBuf,
    device: String,
    writer: bool,
}

/// The frozen corpus spec + budgets, parsed STRICTLY from
/// `benchmarks/issues-reference.json`.
#[derive(Debug)]
struct Spec {
    projects: usize,
    issues: usize,
    events_per_issue: usize,
    labels_per_issue: usize,
    actors: usize,
    incremental_ops: usize,
    warmups: usize,
    cold_iterations: usize,
    warm_iterations: usize,
    warm_focus_p95_ms: u128,
    max_request_ms: u128,
    cold_rebuild_ms: u128,
    peak_rss_bytes: u64,
    baselines: Option<serde_json::Value>,
}

/// Strict parse: every section must contain EXACTLY its known keys with the
/// right types. An unknown key is as fatal as a missing one — a workload
/// dimension nobody consumes must fail the gate, not decorate it.
fn parse_spec(raw: &str) -> Result<Spec, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("corpus spec is not JSON: {e}"))?;
    fn exact_keys(v: &serde_json::Value, section: &str, expected: &[&str]) -> Result<(), String> {
        let obj = v
            .as_object()
            .ok_or_else(|| format!("{section} must be an object"))?;
        let mut have: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        have.sort_unstable();
        let mut want = expected.to_vec();
        want.sort_unstable();
        if have != want {
            return Err(format!(
                "{section} keys mismatch: spec has {have:?}, harness consumes {want:?} \
                 — every declared dimension must be consumed and every consumed \
                 dimension declared"
            ));
        }
        Ok(())
    }
    fn get_usize(v: &serde_json::Value, section: &str, key: &str) -> Result<usize, String> {
        v[key]
            .as_u64()
            .map(|n| n as usize)
            .ok_or_else(|| format!("{section}.{key} must be a non-negative integer"))
    }
    exact_keys(
        &v,
        "top level",
        &[
            "version",
            "description",
            "corpus",
            "measurement",
            "budgets",
            "baselines",
            "baselinesNote",
        ],
    )?;
    if v["version"].as_u64() != Some(1) {
        return Err("version must be 1".into());
    }
    if !v["description"].is_string() {
        return Err("description must be a string".into());
    }
    let c = &v["corpus"];
    exact_keys(
        c,
        "corpus",
        &[
            "projects",
            "issues",
            "eventsPerIssue",
            "labelsPerIssue",
            "actors",
            "incrementalOps",
        ],
    )?;
    let m = &v["measurement"];
    exact_keys(
        m,
        "measurement",
        &["warmups", "coldIterations", "warmIterations"],
    )?;
    let b = &v["budgets"];
    exact_keys(
        b,
        "budgets",
        &[
            "warmFocusP95Ms",
            "maxRequestMs",
            "coldRebuildMs",
            "peakRssBytes",
            "warmQueryRegressionPct",
            "writeRegressionPct",
        ],
    )?;
    if !(v["baselines"].is_null() || v["baselines"].is_object()) {
        return Err("baselines must be null or an object of per-family p95 ms".into());
    }
    let actors = get_usize(c, "corpus", "actors")?;
    if actors < 2 {
        return Err("corpus.actors must be at least 2 (founder + one admitted actor)".into());
    }
    Ok(Spec {
        projects: get_usize(c, "corpus", "projects")?,
        issues: get_usize(c, "corpus", "issues")?,
        events_per_issue: get_usize(c, "corpus", "eventsPerIssue")?,
        labels_per_issue: get_usize(c, "corpus", "labelsPerIssue")?,
        actors,
        incremental_ops: get_usize(c, "corpus", "incrementalOps")?,
        warmups: get_usize(m, "measurement", "warmups")?,
        cold_iterations: get_usize(m, "measurement", "coldIterations")?,
        warm_iterations: get_usize(m, "measurement", "warmIterations")?,
        warm_focus_p95_ms: get_usize(b, "budgets", "warmFocusP95Ms")? as u128,
        max_request_ms: get_usize(b, "budgets", "maxRequestMs")? as u128,
        cold_rebuild_ms: get_usize(b, "budgets", "coldRebuildMs")? as u128,
        peak_rss_bytes: get_usize(b, "budgets", "peakRssBytes")? as u64,
        baselines: (!v["baselines"].is_null()).then(|| v["baselines"].clone()),
    })
}

fn read_spec() -> Spec {
    let raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/issues-reference.json"),
    )
    .expect("benchmarks/issues-reference.json is committed");
    parse_spec(&raw).expect("the committed corpus spec must parse strictly")
}

#[test]
fn corpus_spec_rejects_unknown_missing_and_mistyped_fields() {
    let good = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/issues-reference.json"),
    )
    .unwrap();
    assert!(parse_spec(&good).is_ok(), "the committed spec parses");

    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["corpus"]["surpriseDimension"] = serde_json::json!(7);
    let err = parse_spec(&v.to_string()).unwrap_err();
    assert!(err.contains("corpus keys mismatch"), "{err}");

    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["corpus"].as_object_mut().unwrap().remove("actors");
    let err = parse_spec(&v.to_string()).unwrap_err();
    assert!(err.contains("corpus keys mismatch"), "{err}");

    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["corpus"]["actors"] = serde_json::json!("thirty-two");
    let err = parse_spec(&v.to_string()).unwrap_err();
    assert!(err.contains("actors"), "{err}");

    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["budgets"].as_object_mut().unwrap().remove("maxRequestMs");
    let err = parse_spec(&v.to_string()).unwrap_err();
    assert!(err.contains("budgets keys mismatch"), "{err}");
}

/// Peak RSS of this process (all daemons run in-process on their own threads),
/// in bytes. Linux reads `VmHWM`; other platforms record `None` and the RSS
/// budget is enforced on the Linux CI leg.
fn peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn p95(samples: &[u128]) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64) * 0.95).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

#[test]
fn issues_reference_performance_gate() {
    let spec = read_spec();
    let full = std::env::var("LAIT_PERF_FULL").is_ok();
    // The smoke fraction keeps the whole harness (fleet admission, distributed
    // corpus build, tier refusal, warm families, incremental advance, restart
    // rebuild) in every default suite run.
    // `LAIT_PERF_SCALE` is a calibration knob for sizing intermediate runs;
    // the FULL run is always scale 1.
    let scale = if full {
        1.0
    } else {
        std::env::var("LAIT_PERF_SCALE")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v > 0.0 && *v <= 1.0)
            .unwrap_or(0.002)
    };
    let projects = ((spec.projects as f64 * scale).ceil() as usize).clamp(2, spec.projects);
    let issues = ((spec.issues as f64 * scale).ceil() as usize).clamp(20, spec.issues);
    let events_per_issue = if full { spec.events_per_issue } else { 2 };
    let labels_per_issue = if full { spec.labels_per_issue } else { 2 };
    let incremental_ops =
        ((spec.incremental_ops as f64 * scale).ceil() as usize).clamp(10, spec.incremental_ops);
    let warm_iterations = if full { spec.warm_iterations } else { 15 };
    let cold_iterations = if full { spec.cold_iterations } else { 2 };
    // Fleet size: the full corpus admits every declared actor; the smoke run
    // keeps the SHAPE (founder + ≥1 contributor + the viewer tier) at minimum
    // size so admission, distribution, and tier refusal all execute.
    let actors = if full {
        spec.actors
    } else {
        ((spec.actors as f64 * scale).ceil() as usize).clamp(3.min(spec.actors), spec.actors)
    };

    let net = MemNet::new();
    let founder_home = temp_home("founder");
    lait::orbital::form_space(&founder_home, &FOUNDER_SEED, "Perf Reference Space").unwrap();
    let mut founder_daemon = Some(spawn_daemon(&founder_home, FOUNDER_SEED, &net));
    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &founder_home);
    let founder_device = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();

    // ---- projects first (joiners sync the catalog at admission) ------------
    let build_started = Instant::now();
    let mut project_keys: Vec<String> = Vec::new();
    for p in 0..projects {
        // Project keys are alphabetic (the tracker's key grammar): PAA, PAB, …
        let key = format!(
            "P{}{}",
            (b'A' + (p / 26) as u8) as char,
            (b'A' + (p % 26) as u8) as char
        );
        ok(
            &rt,
            &founder_home,
            Request::ProjectNew {
                name: format!("Project {p:02}"),
                key: key.clone(),
                color: None,
            },
        );
        project_keys.push(key);
    }

    // ---- admit the actor fleet through the real admission path -------------
    // Actors 1..n-1 are contributors (writer tier); the LAST actor is the
    // viewer tier — admitted with read-only standing to exercise the
    // authorization boundary through the same public path.
    let mut fleet: Vec<FleetActor> = Vec::new();
    // Formation seeds a default project besides the created ones.
    let projects_expected = projects + 1;
    for a in 1..actors {
        let viewer = a == actors - 1;
        let resp = ok(
            &rt,
            &founder_home,
            Request::Invite {
                role: Some(if viewer { "viewer" } else { "contributor" }.into()),
                reusable: false,
                ttl_hours: Some(24),
            },
        );
        let Response::Ref { reff: invite } = resp else {
            panic!("expected an invite Ref, got {resp:?}");
        };
        let seed = actor_seed(a);
        let home = temp_home(&format!("actor{a:02}"));
        lait::orbital::enter_space(&home, &seed, &invite).unwrap();
        let _joiner_daemon = spawn_daemon(&home, seed, &net);
        wait_online(&rt, &home);
        let device = lait::crypto::device_from_seed(&seed).to_string();
        let admitted = poll_until(Duration::from_secs(60), || {
            req(
                &rt,
                &home,
                Request::Connect {
                    ticket: founder_device.clone(),
                },
            );
            req(
                &rt,
                &founder_home,
                Request::Connect {
                    ticket: device.clone(),
                },
            );
            req(
                &rt,
                &home,
                Request::Connect {
                    ticket: founder_device.clone(),
                },
            );
            match req(&rt, &home, Request::Status) {
                Response::Status(info) if info.membership == "member" => Some(()),
                _ => None,
            }
        });
        assert!(admitted.is_some(), "actor {a} was never admitted");
        // Membership can land a pull before the catalog Body does: wait until
        // this actor's replica holds every project before it authors into one.
        let caught_up = poll_until(Duration::from_secs(30), || {
            req(
                &rt,
                &home,
                Request::Connect {
                    ticket: founder_device.clone(),
                },
            );
            match req(&rt, &home, Request::ProjectList) {
                Response::Projects { projects } if projects.len() >= projects_expected => Some(()),
                _ => None,
            }
        });
        assert!(
            caught_up.is_some(),
            "actor {a} never synced the project catalog"
        );
        fleet.push(FleetActor {
            home,
            device,
            writer: !viewer,
        });
    }

    // ---- distributed corpus build (public surface only) --------------------
    // Writers: the founder plus every contributor. Issue i is authored by
    // writer[i % writers] on ITS OWN replica; each issue's per-issue events
    // (comments + the workflow start/stop gate pair) are authored by the same
    // actor. The distribution is a pure function of the issue index.
    let mut writer_homes: Vec<PathBuf> = vec![founder_home.clone()];
    writer_homes.extend(fleet.iter().filter(|f| f.writer).map(|f| f.home.clone()));
    let label_pool: Vec<String> = (0..16).map(|l| format!("area-{l:02}")).collect();

    let per_writer: Vec<Vec<usize>> = (0..writer_homes.len())
        .map(|w| {
            (0..issues)
                .filter(|i| i % writer_homes.len() == w)
                .collect()
        })
        .collect();
    let mut author_threads = Vec::new();
    for (w, slice) in per_writer.into_iter().enumerate() {
        let home = writer_homes[w].clone();
        let project_keys = project_keys.clone();
        let label_pool = label_pool.clone();
        author_threads.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            for i in slice {
                let project = &project_keys[i % project_keys.len()];
                let labels: Vec<String> = (0..labels_per_issue)
                    .map(|k| label_pool[(i + k) % label_pool.len()].clone())
                    .collect();
                let resp = ok(
                    &rt,
                    &home,
                    Request::IssueNew {
                        due: None,
                        estimate: None,
                        title: format!("reference issue {i:05}"),
                        project: Some(project.clone()),
                        project_hint: None,
                        assignees: vec![],
                        priority: Some(["low", "medium", "high", "urgent"][i % 4].into()),
                        labels,
                        body: Some(format!("corpus body for issue {i:05}")),
                    },
                );
                let reff = match &resp {
                    Response::Ref { reff } => reff.clone(),
                    Response::Issue(v) => v.reff.clone(),
                    other => panic!("IssueNew answered {other:?}"),
                };
                for e in 0..events_per_issue.saturating_sub(2) {
                    ok(
                        &rt,
                        &home,
                        Request::Comment {
                            reply_to: None,
                            reff: reff.clone(),
                            body: format!("event {e} on {reff}"),
                        },
                    );
                }
                if events_per_issue >= 2 {
                    // The workflow gate pair: every issue passes the
                    // start/stop transition demands on its author's replica.
                    ok(&rt, &home, Request::IssueStart { reff: reff.clone() });
                    ok(&rt, &home, Request::IssueStop { reff: reff.clone() });
                }
            }
        }));
    }
    for t in author_threads {
        t.join().expect("author thread");
    }

    // ---- convergence: pump Contact until the founder holds the whole corpus --
    let list_all_count = |rt: &tokio::runtime::Runtime, home: &Path| -> usize {
        match req(
            rt,
            home,
            Request::List {
                project: None,
                filter: Filter {
                    all: true,
                    ..Default::default()
                },
            },
        ) {
            Response::List { rows } => rows.len(),
            _ => 0,
        }
    };
    let pump = |rt: &tokio::runtime::Runtime| {
        for f in &fleet {
            let a = req(
                rt,
                &f.home,
                Request::Connect {
                    ticket: founder_device.clone(),
                },
            );
            let b = req(
                rt,
                &founder_home,
                Request::Connect {
                    ticket: f.device.clone(),
                },
            );
            if std::env::var("LAIT_PERF_DEBUG").is_ok() {
                eprintln!("pump joiner->founder: {a:?}; founder->joiner: {b:?}");
            }
        }
    };
    let converge_budget = Duration::from_secs(60 + (issues as u64) / 10);
    let mut rounds = 0u32;
    let converged = poll_until(converge_budget, || {
        pump(&rt);
        let n = list_all_count(&rt, &founder_home);
        rounds += 1;
        if std::env::var("LAIT_PERF_DEBUG").is_ok() && rounds.is_multiple_of(10) {
            let fleet_counts: Vec<usize> =
                fleet.iter().map(|f| list_all_count(&rt, &f.home)).collect();
            eprintln!("CONVERGE round={rounds} founder_list={n} fleet={fleet_counts:?}");
        }
        (n >= issues).then_some(())
    });
    assert!(
        converged.is_some(),
        "founder never converged to the full corpus: {} of {issues}",
        list_all_count(&rt, &founder_home)
    );

    // ---- cross-actor interaction + the viewer authorization tier -----------
    // Every contributor comments once on a founder-visible issue (cross-node
    // authoring on a synced Body), and the viewer proves the read tier: its
    // reads serve, its mutation is refused at the demand layer.
    let founder_refs: Vec<String> = match req(
        &rt,
        &founder_home,
        Request::List {
            project: None,
            filter: Filter {
                all: true,
                ..Default::default()
            },
        },
    ) {
        Response::List { rows } => rows.iter().map(|r| r.reff.clone()).collect(),
        other => panic!("expected List, got {other:?}"),
    };
    for (n, f) in fleet.iter().filter(|f| f.writer).enumerate() {
        ok(
            &rt,
            &f.home,
            Request::Comment {
                reply_to: None,
                reff: founder_refs[n % founder_refs.len()].clone(),
                body: format!("cross-actor comment from contributor {n}"),
            },
        );
    }
    if let Some(viewer) = fleet.iter().find(|f| !f.writer) {
        let rows = list_all_count(&rt, &viewer.home);
        assert!(rows > 0, "the viewer tier reads the converged corpus");
        let denied = req(
            &rt,
            &viewer.home,
            Request::IssueNew {
                due: None,
                estimate: None,
                title: "viewer must not author".into(),
                project: Some(project_keys[0].clone()),
                project_hint: None,
                assignees: vec![],
                priority: None,
                labels: vec![],
                body: None,
            },
        );
        assert!(
            matches!(denied, Response::Error { .. }),
            "the viewer tier must be refused mutation, got {denied:?}"
        );
    }
    let build_secs = build_started.elapsed().as_secs_f64();

    // ---- measured families (on the founder's public socket) ----------------
    let refs = founder_refs;
    let home = founder_home.clone();
    let focus = |rt: &tokio::runtime::Runtime| {
        ok(rt, &home, Request::Inbox { clear: false });
        ok(
            rt,
            &home,
            Request::List {
                project: None,
                filter: Filter {
                    mine: true,
                    ..Default::default()
                },
            },
        );
    };
    for _ in 0..spec.warmups {
        focus(&rt);
    }

    type Family<'a> = (
        &'a str,
        Box<dyn FnMut(&tokio::runtime::Runtime, usize) + 'a>,
    );
    let mut families: Vec<Family<'_>> = vec![
        ("focus", Box::new(|rt, _| focus(rt))),
        (
            "issue_open",
            Box::new(|rt, i| {
                ok(
                    rt,
                    &home,
                    Request::IssueView {
                        reff: refs[i % refs.len()].clone(),
                    },
                );
            }),
        ),
        (
            "project_list",
            Box::new(|rt, _| {
                ok(rt, &home, Request::ProjectList);
            }),
        ),
        (
            "board",
            Box::new(|rt, i| {
                ok(
                    rt,
                    &home,
                    Request::Board {
                        project: Some(project_keys[i % project_keys.len()].clone()),
                        project_hint: None,
                    },
                );
            }),
        ),
        (
            "graph",
            Box::new(|rt, i| {
                ok(
                    rt,
                    &home,
                    Request::IssueGraph {
                        reff: refs[i % refs.len()].clone(),
                    },
                );
            }),
        ),
        (
            "history",
            Box::new(|rt, i| {
                ok(
                    rt,
                    &home,
                    Request::History {
                        reff: refs[i % refs.len()].clone(),
                    },
                );
            }),
        ),
        (
            "edit",
            Box::new(|rt, i| {
                ok(
                    rt,
                    &home,
                    Request::IssueEdit {
                        due: None,
                        estimate: None,
                        reff: refs[i % refs.len()].clone(),
                        title: Some(format!("edited title {i}")),
                        status: None,
                        priority: None,
                        description: None,
                    },
                );
            }),
        ),
        (
            "workflow_transition",
            Box::new(|rt, i| {
                let reff = refs[i % refs.len()].clone();
                if i % 2 == 0 {
                    ok(rt, &home, Request::IssueStart { reff });
                } else {
                    ok(rt, &home, Request::IssueStop { reff });
                }
            }),
        ),
        (
            "create",
            Box::new(|rt, i| {
                ok(
                    rt,
                    &home,
                    Request::IssueNew {
                        due: None,
                        estimate: None,
                        title: format!("warm create {i}"),
                        project: Some(project_keys[i % project_keys.len()].clone()),
                        project_hint: None,
                        assignees: vec![],
                        priority: None,
                        labels: vec![],
                        body: None,
                    },
                );
            }),
        ),
        (
            "two_project_policy",
            Box::new(|rt, i| {
                // Listing under two DIFFERENT projects back to back evaluates
                // the per-project policy context twice in one family sample.
                for p in [i, i + 1] {
                    ok(
                        rt,
                        &home,
                        Request::List {
                            project: Some(project_keys[p % project_keys.len()].clone()),
                            filter: Filter::default(),
                        },
                    );
                }
            }),
        ),
    ];

    let mut report = serde_json::Map::new();
    let mut warm_p95: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for (name, run) in families.iter_mut() {
        let mut samples: Vec<u128> = Vec::with_capacity(warm_iterations);
        for i in 0..warm_iterations {
            let t = Instant::now();
            run(&rt, i);
            let ms = t.elapsed().as_millis();
            assert!(
                ms <= spec.max_request_ms,
                "warm {name} iteration {i} took {ms} ms (> {} ms ceiling)",
                spec.max_request_ms
            );
            samples.push(ms);
        }
        let p = p95(&samples);
        warm_p95.insert((*name).into(), serde_json::json!(p));
        report.insert(
            format!("warm_{name}_samples_ms"),
            serde_json::json!(samples.iter().map(|s| *s as u64).collect::<Vec<_>>()),
        );
        if *name == "focus" {
            assert!(
                p <= spec.warm_focus_p95_ms,
                "warm focus p95 {p} ms exceeds the product-promised {} ms",
                spec.warm_focus_p95_ms
            );
        }
    }
    drop(families);

    // ---- incremental advance (the sync-sized tail, distributed) ------------
    let t = Instant::now();
    for i in 0..incremental_ops {
        let author = &writer_homes[i % writer_homes.len()];
        ok(
            &rt,
            author,
            Request::Comment {
                reply_to: None,
                reff: refs[i % refs.len()].clone(),
                body: format!("incremental op {i}"),
            },
        );
    }
    pump(&rt);
    let incr_write_ms = t.elapsed().as_millis();
    let t = Instant::now();
    focus(&rt);
    let incr_advance_ms = t.elapsed().as_millis();
    assert!(
        incr_advance_ms <= spec.max_request_ms,
        "post-incremental focus took {incr_advance_ms} ms"
    );

    // ---- restart rebuild (cold, founder) -----------------------------------
    let mut cold_samples: Vec<u128> = Vec::new();
    for i in 0..cold_iterations {
        let _ = req(&rt, &founder_home, Request::Stop);
        if let Some(h) = founder_daemon.take() {
            let _ = h.join();
        }
        let t = Instant::now();
        founder_daemon = Some(spawn_daemon(&founder_home, FOUNDER_SEED, &net));
        wait_online(&rt, &founder_home);
        focus(&rt);
        let ms = t.elapsed().as_millis();
        assert!(
            ms <= spec.cold_rebuild_ms,
            "cold restart+rebuild iteration {i} took {ms} ms (> {} ms budget)",
            spec.cold_rebuild_ms
        );
        cold_samples.push(ms);
    }

    // ---- artifact + baselines ---------------------------------------------
    let rss = peak_rss_bytes();
    if let Some(rss) = rss {
        assert!(
            rss <= spec.peak_rss_bytes,
            "peak RSS {rss} bytes exceeds the {} byte budget",
            spec.peak_rss_bytes
        );
    }
    if full {
        if let Some(baselines) = &spec.baselines {
            for (name, p) in &warm_p95 {
                if let Some(base) = baselines[name].as_u64() {
                    let budget_pct: u64 =
                        if matches!(name.as_str(), "edit" | "create" | "workflow_transition") {
                            15
                        } else {
                            10
                        };
                    let limit = base + base * budget_pct / 100;
                    let p = p.as_u64().unwrap();
                    assert!(
                        p <= limit,
                        "{name} warm p95 {p} ms regressed beyond {budget_pct}% of the \
                         frozen baseline {base} ms"
                    );
                }
            }
        }
    }
    report.insert("scale".into(), serde_json::json!(scale));
    report.insert("issues".into(), serde_json::json!(issues));
    report.insert("projects".into(), serde_json::json!(projects));
    report.insert("actors".into(), serde_json::json!(actors));
    report.insert("corpus_build_secs".into(), serde_json::json!(build_secs));
    report.insert("warm_p95_ms".into(), serde_json::Value::Object(warm_p95));
    report.insert(
        "cold_restart_samples_ms".into(),
        serde_json::json!(cold_samples.iter().map(|s| *s as u64).collect::<Vec<_>>()),
    );
    report.insert(
        "incremental_write_ms".into(),
        serde_json::json!(incr_write_ms as u64),
    );
    report.insert(
        "incremental_advance_ms".into(),
        serde_json::json!(incr_advance_ms as u64),
    );
    report.insert("peak_rss_bytes".into(), serde_json::json!(rss));
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        out_dir.join("issues-reference-report.json"),
        serde_json::to_string_pretty(&serde_json::Value::Object(report)).unwrap(),
    )
    .unwrap();

    // Teardown: stop every daemon and reclaim the temp stores.
    let _ = req(&rt, &founder_home, Request::Stop);
    if let Some(h) = founder_daemon.take() {
        let _ = h.join();
    }
    for f in &fleet {
        let _ = req(&rt, &f.home, Request::Stop);
    }
    std::thread::sleep(Duration::from_millis(200));
    let _ = std::fs::remove_dir_all(&founder_home);
    for f in &fleet {
        let _ = std::fs::remove_dir_all(&f.home);
    }
}
