mod json;
mod layer1_source;
mod layer2_build;
mod layer3_binary;
mod report;
mod negative_controls;

use std::path::PathBuf;
use report::Verdict;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let workspace_root = find_workspace_root(&args);
    let crates_dir = workspace_root.join("crates");
    let reports_dir = workspace_root.join("reports");
    let tmp_dir = workspace_root.join(".pure_wad18_tmp");
    std::fs::create_dir_all(&reports_dir).ok();
    std::fs::create_dir_all(&tmp_dir).ok();

    let cargo_bin = find_cargo();
    let timestamp = iso_timestamp();

    eprintln!("[pure-wad18] workspace: {}", workspace_root.display());
    eprintln!("[pure-wad18] timestamp: {}", timestamp);

    // ── Layer 1 ──────────────────────────────────────────────────────────────
    eprintln!("\n[Layer 1] Scanning source files for float tokens...");
    let (files_scanned, l1_findings) = layer1_source::scan_crates_dir(&crates_dir);
    let l1_pass = l1_findings.is_empty();
    eprintln!(
        "[Layer 1] {} — {} files, {} finding(s)",
        if l1_pass { "PASS" } else { "FAIL" },
        files_scanned,
        l1_findings.len()
    );
    for f in &l1_findings {
        eprintln!("  [L1] {}:{} `{}` — {}", f.file, f.line, f.token, f.context);
    }

    // ── Layer 2 ──────────────────────────────────────────────────────────────
    eprintln!("\n[Layer 2] Building kernel crates for float-free target...");
    // Try to install wasm32v1-none target (no-op if already installed or offline)
    let _ = std::process::Command::new("rustup")
        .args(["target", "add", layer2_build::PRIMARY_TARGET])
        .output();
    let build = layer2_build::run_build(&workspace_root, &cargo_bin);
    eprintln!(
        "[Layer 2] {} — target: {}, {} error(s), {} artifact(s)",
        if build.passed { "PASS" } else { "FAIL" },
        build.target,
        build.error_lines.len(),
        build.artifacts.len()
    );
    for line in &build.error_lines { eprintln!("  [L2] {}", line); }
    for art in &build.artifacts { eprintln!("  [L2] artifact: {}", art); }

    // ── Layer 3 ──────────────────────────────────────────────────────────────
    eprintln!("\n[Layer 3] Scanning binary artifacts for float opcodes...");
    let binary = layer3_binary::scan_artifacts(&build.artifacts);
    eprintln!(
        "[Layer 3] {} — {} artifact(s) scanned, {} finding(s)",
        if binary.passed { "PASS" } else { "FAIL" },
        binary.artifacts_scanned.len(),
        binary.findings.len()
    );
    for f in &binary.findings {
        eprintln!("  [L3] {} @ {} — `{}`", f.artifact, f.location, f.opcode);
    }

    // ── Negative Controls ─────────────────────────────────────────────────────
    eprintln!("\n[Negative Controls] Running 3 negative controls...");
    let controls = negative_controls::run_all_controls(&tmp_dir, &cargo_bin);
    for ctrl in &controls {
        eprintln!(
            "  [{}] {} — {}: {}",
            ctrl.control_id,
            if ctrl.passed { "CAUGHT ✓" } else { "MISSED ✗" },
            ctrl.description,
            ctrl.details
        );
    }

    // ── Reports ───────────────────────────────────────────────────────────────
    let md_path = reports_dir.join("pure_wad18_report.md");
    let json_path = reports_dir.join("pure_wad18_report.json");

    let verdict = report::write_reports(
        &crates_dir.to_string_lossy(),
        &timestamp,
        files_scanned,
        &l1_findings,
        &build,
        &binary,
        &controls,
        &md_path,
        &json_path,
    );

    let nc_caught = controls.iter().filter(|c| c.passed).count();
    eprintln!("\n══════════════════════════════════════════════");
    eprintln!("  VERDICT: {}", verdict);
    eprintln!("  Negative controls: {}/3 caught", nc_caught);
    eprintln!("══════════════════════════════════════════════");
    eprintln!("  Markdown: {}", md_path.display());
    eprintln!("  JSON:     {}", json_path.display());

    // Cleanup
    std::fs::remove_dir_all(&tmp_dir).ok();

    let success = verdict == Verdict::VERIFIED && nc_caught == 3;
    std::process::exit(if success { 0 } else { 1 });
}

fn find_workspace_root(args: &[String]) -> PathBuf {
    for i in 0..args.len() {
        if args[i] == "--workspace" && i + 1 < args.len() {
            return PathBuf::from(&args[i + 1]);
        }
    }
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..8 {
        let ct = dir.join("Cargo.toml");
        if ct.exists() {
            if let Ok(c) = std::fs::read_to_string(&ct) {
                if c.contains("[workspace]") { return dir; }
            }
        }
        if !dir.pop() { break; }
    }
    PathBuf::from(".")
}

fn find_cargo() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let c = format!("{}/.cargo/bin/cargo", home);
    if std::path::Path::new(&c).exists() { return c; }
    "cargo".to_string()
}

fn iso_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let (y, mo, d) = days_to_ymd(secs / 86400);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let yd = if is_leap(y) { 366 } else { 365 };
        if days < yd { break; }
        days -= yd; y += 1;
    }
    let md = [31u64, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 1u64;
    for &d in &md { if days < d { break; } days -= d; mo += 1; }
    (y, mo, days + 1)
}

fn is_leap(y: u64) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }
