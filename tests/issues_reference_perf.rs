//! M6 — the IssuesWorld reference performance gate (plan 50).
//!
//! Builds the frozen corpus described by `benchmarks/issues-reference.json`
//! **exclusively through the public daemon/control surface** (a real daemon on
//! a real control socket, in-memory transport), then measures cold and warm
//! distributions for the product-promised request families: bare focus
//! (inbox + my issues), issue open, project list, board, graph, history,
//! create/edit, workflow transition, two-project policy evaluation, restart
//! rebuild, and incremental advance after a sync-sized tail of extra
//! operations.
//!
//! Scale: the default run uses a small deterministic fraction of the corpus so
//! every CI leg exercises the whole harness and the absolute budgets
//! (per-request ceiling, restart budget, focus p95). The full 50k-issue corpus
//! runs with `LAIT_PERF_FULL=1` in the dedicated `orbital-perf` CI job, which
//! uploads the sample artifact (`target/perf/issues-reference-report.json`,
//! all samples + p95s + peak RSS) and gates p95 regressions once baselines are
//! frozen in the spec (`baselines` is null until the first reviewed full run).
//!
//! Root-consistency note: the daemon serves every response from one docked
//! Session snapshot — there is no derived product cache yet, so no mixed-root
//! output is constructible at this surface; runtime-level root labeling and
//! the frontier compare-and-swap are proven by `independent_world` and
//! `world_policy`. A product-side cache, when introduced, must label entries
//! by exact Manifest root and extend this gate with the injection proof.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Filter, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [173u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

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

fn temp_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-perf-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write the orbital identity seed where the daemon's `load_or_create_identity`
/// expects it (the same file the real `lait init` provisions). Collapses the
/// identity dir onto `home` via `$LAIT_HOME`, exactly as the lifecycle suite
/// does — this binary holds a single test, so the process-global env is safe.
fn write_identity(home: &Path, seed: &[u8; 32]) {
    std::env::set_var("LAIT_HOME", home);
    std::fs::write(
        home.join("secret.key"),
        data_encoding::HEXLOWER.encode(seed),
    )
    .unwrap();
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

fn spawn_daemon(home: &Path, net: &MemNet) -> std::thread::JoinHandle<()> {
    let daemon_home = home.to_path_buf();
    let daemon_net = net.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) = run_orbital_daemon(daemon_home, &MemFactory(daemon_net)).await {
                eprintln!("PERF DAEMON ERR: {e:#}");
            }
        });
    })
}

fn wait_online(rt: &tokio::runtime::Runtime, home: &Path) {
    let online = poll_until(Duration::from_secs(30), || {
        matches!(req(rt, home, Request::Status), Response::Status(_)).then_some(())
    });
    assert!(online.is_some(), "the daemon never answered Status");
}

/// The frozen corpus spec + budgets, read from `benchmarks/issues-reference.json`.
struct Spec {
    projects: usize,
    issues: usize,
    events_per_issue: usize,
    labels_per_issue: usize,
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

fn read_spec() -> Spec {
    let raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/issues-reference.json"),
    )
    .expect("benchmarks/issues-reference.json is committed");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let c = &v["corpus"];
    let m = &v["measurement"];
    let b = &v["budgets"];
    Spec {
        projects: c["projects"].as_u64().unwrap() as usize,
        issues: c["issues"].as_u64().unwrap() as usize,
        events_per_issue: c["eventsPerIssue"].as_u64().unwrap() as usize,
        labels_per_issue: c["labelsPerIssue"].as_u64().unwrap() as usize,
        incremental_ops: c["incrementalOps"].as_u64().unwrap() as usize,
        warmups: m["warmups"].as_u64().unwrap() as usize,
        cold_iterations: m["coldIterations"].as_u64().unwrap() as usize,
        warm_iterations: m["warmIterations"].as_u64().unwrap() as usize,
        warm_focus_p95_ms: b["warmFocusP95Ms"].as_u64().unwrap() as u128,
        max_request_ms: b["maxRequestMs"].as_u64().unwrap() as u128,
        cold_rebuild_ms: b["coldRebuildMs"].as_u64().unwrap() as u128,
        peak_rss_bytes: b["peakRssBytes"].as_u64().unwrap(),
        baselines: (!v["baselines"].is_null()).then(|| v["baselines"].clone()),
    }
}

/// Peak RSS of this process (the daemon runs in-process on its own thread), in
/// bytes. Linux reads `VmHWM`; other platforms record `None` and the RSS
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
    // The smoke fraction keeps the whole harness (corpus build, warm families,
    // incremental advance, restart rebuild) in every default suite run.
    let scale = if full { 1.0 } else { 0.002 };
    let projects = ((spec.projects as f64 * scale).ceil() as usize).clamp(2, spec.projects);
    let issues = ((spec.issues as f64 * scale).ceil() as usize).clamp(20, spec.issues);
    let events_per_issue = if full { spec.events_per_issue } else { 2 };
    let labels_per_issue = if full { spec.labels_per_issue } else { 2 };
    let incremental_ops =
        ((spec.incremental_ops as f64 * scale).ceil() as usize).clamp(10, spec.incremental_ops);
    let warm_iterations = if full { spec.warm_iterations } else { 15 };
    let cold_iterations = if full { spec.cold_iterations } else { 2 };

    let home = temp_home();
    let net = MemNet::new();
    write_identity(&home, &FOUNDER_SEED);
    lait::orbital::form_space(&home, &FOUNDER_SEED, "Perf Reference Space").unwrap();
    let mut daemon = Some(spawn_daemon(&home, &net));
    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);

    // ---- corpus build (public surface only) --------------------------------
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
            &home,
            Request::ProjectNew {
                name: format!("Project {p:02}"),
                key: key.clone(),
            },
        );
        project_keys.push(key);
    }
    let label_pool: Vec<String> = (0..16).map(|l| format!("area-{l:02}")).collect();
    let mut refs: Vec<String> = Vec::with_capacity(issues);
    for i in 0..issues {
        let project = &project_keys[i % project_keys.len()];
        let labels: Vec<String> = (0..labels_per_issue)
            .map(|k| label_pool[(i + k) % label_pool.len()].clone())
            .collect();
        let resp = ok(
            &rt,
            &home,
            Request::IssueNew {
                title: format!("reference issue {i:05}"),
                project: Some(project.clone()),
                project_hint: None,
                // Assignment lands via the work-state Start below (start
                // assigns + activates), which is what populates `focus`.
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
        // Per-issue semantic events: comments plus a status flip pair, the
        // event mix the history/board projections must digest.
        for e in 0..events_per_issue.saturating_sub(2) {
            ok(
                &rt,
                &home,
                Request::Comment {
                    reff: reff.clone(),
                    body: format!("event {e} on {reff}"),
                },
            );
        }
        if events_per_issue >= 2 {
            ok(&rt, &home, Request::IssueStart { reff: reff.clone() });
            ok(&rt, &home, Request::IssueStop { reff: reff.clone() });
        }
        refs.push(reff);
    }
    let build_secs = build_started.elapsed().as_secs_f64();

    // ---- measured families -------------------------------------------------
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

    let mut families: Vec<(&str, Box<dyn FnMut(&tokio::runtime::Runtime, usize)>)> = vec![
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

    // ---- incremental advance ----------------------------------------------
    let t = Instant::now();
    for i in 0..incremental_ops {
        ok(
            &rt,
            &home,
            Request::Comment {
                reff: refs[i % refs.len()].clone(),
                body: format!("incremental op {i}"),
            },
        );
    }
    let incr_write_ms = t.elapsed().as_millis();
    let t = Instant::now();
    focus(&rt);
    let incr_advance_ms = t.elapsed().as_millis();
    assert!(
        incr_advance_ms <= spec.max_request_ms,
        "post-incremental focus took {incr_advance_ms} ms"
    );

    // ---- restart rebuild (cold) -------------------------------------------
    let mut cold_samples: Vec<u128> = Vec::new();
    for i in 0..cold_iterations {
        let _ = req(&rt, &home, Request::Stop);
        if let Some(h) = daemon.take() {
            let _ = h.join();
        }
        let t = Instant::now();
        daemon = Some(spawn_daemon(&home, &net));
        wait_online(&rt, &home);
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

    let _ = req(&rt, &home, Request::Stop);
    if let Some(h) = daemon.take() {
        let _ = h.join();
    }
    let _ = std::fs::remove_dir_all(&home);
}
