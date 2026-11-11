// PURE WAD-18 Verification Pipeline — Layer 2: Float-Free Build
//
// Target choice: wasm32v1-none
//   WebAssembly 2.0 component model, no OS, no std, no hardware FP.
//   Any float op must appear as an explicit WASM opcode (f32.add etc.),
//   making Layer 3 binary scan exhaustive and deterministic.
//   Fallback: thumbv6m-none-eabi (Cortex-M0, software-float, no FPU registers).

use std::path::Path;
use std::process::Command;
use crate::json::json_str;

pub const PRIMARY_TARGET: &str = "wasm32v1-none";
pub const _FALLBACK_TARGET: &str = "thumbv6m-none-eabi";

#[derive(Debug, Clone)]
pub struct BuildResult {
    pub target: String,
    pub passed: bool,
    pub error_lines: Vec<String>,
    pub artifacts: Vec<String>,
    pub target_justification: String,
}

impl BuildResult {
    pub fn to_json(&self) -> String {
        let errors: Vec<String> = self.error_lines.iter().map(|s| json_str(s)).collect();
        let artifacts: Vec<String> = self.artifacts.iter().map(|s| json_str(s)).collect();
        format!(
            r#"{{
    "target": {},
    "passed": {},
    "target_justification": {},
    "error_lines": [{}],
    "artifacts": [{}]
  }}"#,
            json_str(&self.target),
            self.passed,
            json_str(&self.target_justification),
            errors.join(", "),
            artifacts.join(", "),
        )
    }
}

fn find_rustup() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let p = format!("{}/.cargo/bin/rustup", home);
    if std::path::Path::new(&p).exists() { return p; }
    "rustup".to_string()
}

pub fn install_target_if_missing(target: &str) {
    let rustup = find_rustup();
    let _ = Command::new(&rustup)
        .args(["target", "add", target])
        .output();
}

pub fn run_build(workspace_root: &Path, cargo_bin: &str) -> BuildResult {
    let target = choose_target();
    let justification = if target == PRIMARY_TARGET {
        "wasm32v1-none: WebAssembly 2.0, no OS, no std, no hardware FP. \
         Float ops must appear as named WASM opcodes (f32.const, f64.add etc.), \
         making Layer 3 binary scan exhaustive and deterministic. \
         Preferred over wasm32-unknown-unknown (may carry hidden allocator shims)."
            .to_string()
    } else {
        format!(
            "{}: soft-float Cortex-M0 fallback; wasm32v1-none not installed. \
             Layer 3 uses objdump ELF scan for FP instructions.",
            target
        )
    };

    // Attempt to install the target first
    install_target_if_missing(&target);

    let home = std::env::var("HOME").unwrap_or_default();
    let path_env = format!("{}/.cargo/bin:{}", home, std::env::var("PATH").unwrap_or_default());

    let output = Command::new(cargo_bin)
        .args([
            "build",
            "--release",
            "--target",
            &target,
            // Layer 2 scopes to the normative WAD-18 arithmetic kernel only.
            // `ssi-kernel`, `ssi-gate`, etc. use `std` (Vec, Box) and require
            // a `no_std` + `alloc` refactor to compile for wasm32v1-none — tracked
            // as Phase 1c follow-on. The arithmetic crate is the float-risk surface.
            "--package",
            "wad18",
        ])
        .current_dir(workspace_root)
        .env("CARGO_TERM_COLOR", "never")
        .env("PATH", &path_env)
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let error_lines: Vec<String> = stderr
                .lines()
                .filter(|l| l.contains("error[") || l.starts_with("error"))
                .map(|l| l.to_string())
                .collect();

            // Collect artifacts from target dir
            let target_dir = workspace_root.join("target").join(&target).join("release");
            let mut artifacts = Vec::new();
            collect_artifacts(&target_dir, &mut artifacts);

            BuildResult {
                target,
                passed: out.status.success(),
                error_lines,
                artifacts,
                target_justification: justification,
            }
        }
        Err(e) => BuildResult {
            target,
            passed: false,
            error_lines: vec![format!("Failed to invoke cargo: {}", e)],
            artifacts: vec![],
            target_justification: justification,
        },
    }
}

fn collect_artifacts(dir: &Path, artifacts: &mut Vec<String>) {
    if !dir.exists() { return; }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            let size = p.metadata().map(|m| m.len()).unwrap_or(0);
            // Collect .wasm files, .rlib archives, or ELF executables
            if name.ends_with(".wasm") || name.ends_with(".rlib") || (!name.contains('.') && size > 1024) {
                artifacts.push(p.to_string_lossy().to_string());
            }
        }
    }
}

pub fn choose_target() -> String {
    // 1. Check if wasm32v1-none sysroot directory exists directly
    if let Ok(home) = std::env::var("HOME") {
        let rustlib = Path::new(&home).join(".rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib").join(PRIMARY_TARGET);
        if rustlib.exists() {
            return PRIMARY_TARGET.to_string();
        }
    }
    // 2. Query rustup installed targets
    let rustup = find_rustup();
    if let Ok(out) = Command::new(&rustup).args(["target", "list", "--installed"]).output() {
        if String::from_utf8_lossy(&out.stdout).contains(PRIMARY_TARGET) {
            return PRIMARY_TARGET.to_string();
        }
    }
    // 3. Default to PRIMARY_TARGET (pinned normative target)
    PRIMARY_TARGET.to_string()
}
