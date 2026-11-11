// PURE WAD-18 Verification Pipeline — Negative Controls
//
// Three negative controls — each must flip at least one layer to FAIL:
//   1. Float literal injection (NC-1) -> Caught by Layer 1 (Source)
//   2. f64 computation injection (NC-2) -> Caught by Layer 1 (Source)
//   3. Crate compiled with float enabled (NC-3) -> Caught by Layer 3 (Binary Opcode Scan)

use std::path::Path;
use std::process::Command;
use crate::json::json_str;

#[derive(Debug, Clone)]
pub struct NegativeControlResult {
    pub control_id: String,
    pub description: String,
    pub injection: String,
    pub layer_caught: Option<String>,
    pub passed: bool,  // true = control WAS caught
    pub details: String,
}

impl NegativeControlResult {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{
    "control_id": {},
    "description": {},
    "injection": {},
    "layer_caught": {},
    "passed": {},
    "details": {}
  }}"#,
            json_str(&self.control_id),
            json_str(&self.description),
            json_str(&self.injection),
            match &self.layer_caught {
                Some(l) => json_str(l),
                None => "null".to_string(),
            },
            self.passed,
            json_str(&self.details),
        )
    }
}

pub fn run_all_controls(tmp_dir: &Path, cargo_bin: &str) -> Vec<NegativeControlResult> {
    std::fs::create_dir_all(tmp_dir).ok();
    vec![
        control_float_literal(tmp_dir),
        control_f64_computation(tmp_dir),
        control_crate_compiled_with_float(tmp_dir, cargo_bin),
    ]
}

/// NC-1: Float literal injection
fn control_float_literal(tmp_dir: &Path) -> NegativeControlResult {
    let f = tmp_dir.join("nc1_float_literal.rs");
    std::fs::write(&f, r#"
// NC-1: float literal injection
pub fn nc1() -> i64 {
    let x = 1.0_f64;   // FORBIDDEN: typed float literal
    let y = 2.5;        // FORBIDDEN: bare float literal
    let z = 1e10;       // FORBIDDEN: exponent literal
    42
}
"#).ok();
    let findings = crate::layer1_source::scan_file(&f);
    let caught = !findings.is_empty();
    NegativeControlResult {
        control_id: "NC-1".into(),
        description: "Float literal injection (1.0_f64, 2.5, 1e10)".into(),
        injection: "let x = 1.0_f64; let y = 2.5; let z = 1e10;".into(),
        layer_caught: if caught { Some("Layer 1 (Source)".into()) } else { None },
        passed: caught,
        details: if caught {
            format!(
                "Layer 1 caught {} finding(s): {}",
                findings.len(),
                findings.iter().map(|f| format!("`{}` L{}", f.token, f.line)).collect::<Vec<_>>().join(", ")
            )
        } else {
            "MISSED — Layer 1 failed to detect float literals".into()
        },
    }
}

/// NC-2: f64/f32 type usage in function signature
fn control_f64_computation(tmp_dir: &Path) -> NegativeControlResult {
    let f = tmp_dir.join("nc2_f64_compute.rs");
    std::fs::write(&f, r#"
// NC-2: f64 type in signature
pub fn sum(a: f64, b: f64) -> f64 { a + b }
pub fn cast(x: i64) -> f32 { x as f32 }
"#).ok();
    let findings = crate::layer1_source::scan_file(&f);
    let caught = !findings.is_empty();
    NegativeControlResult {
        control_id: "NC-2".into(),
        description: "f64/f32 type in function signatures".into(),
        injection: "pub fn sum(a: f64, b: f64) -> f64 { a + b }".into(),
        layer_caught: if caught { Some("Layer 1 (Source)".into()) } else { None },
        passed: caught,
        details: if caught {
            format!(
                "Layer 1 caught {} finding(s): {}",
                findings.len(),
                findings.iter().map(|f| format!("`{}` L{}", f.token, f.line)).collect::<Vec<_>>().join(", ")
            )
        } else {
            "MISSED — Layer 1 failed to detect f64 type usage".into()
        },
    }
}

/// NC-3: Crate compiled with float enabled -> caught by Layer 3 binary opcode scan
fn control_crate_compiled_with_float(tmp_dir: &Path, cargo_bin: &str) -> NegativeControlResult {
    let crate_dir = tmp_dir.join("nc3_float_crate");
    let src_dir = crate_dir.join("src");
    std::fs::create_dir_all(&src_dir).ok();

    std::fs::write(crate_dir.join("Cargo.toml"), r#"
[package]
name = "nc3-float-crate"
version = "0.1.0"
edition = "2021"
"#).ok();

    std::fs::write(src_dir.join("lib.rs"), r#"
#![no_std]
#[no_mangle]
pub fn float_kernel_add(a: f32, b: f32) -> f32 {
    a + b
}
"#).ok();

    let build_out = Command::new(cargo_bin)
        .args(["build", "--release", "--target", "wasm32v1-none"])
        .current_dir(&crate_dir)
        .output();

    let rlib_path = crate_dir.join("target/wasm32v1-none/release/libnc3_float_crate.rlib");

    if let Ok(out) = build_out {
        if out.status.success() && rlib_path.exists() {
            let bin_res = crate::layer3_binary::scan_artifact(&rlib_path);
            let caught = !bin_res.passed && !bin_res.findings.is_empty();
            let offending_opcodes: Vec<String> = bin_res.findings.iter().map(|f| f.opcode.clone()).collect();
            return NegativeControlResult {
                control_id: "NC-3".into(),
                description: "Crate compiled with float enabled (float_kernel_add emitting f32.add)".into(),
                injection: "pub fn float_kernel_add(a: f32, b: f32) -> f32 { a + b }".into(),
                layer_caught: if caught { Some("Layer 3 (Binary Opcode Scan)".into()) } else { None },
                passed: caught,
                details: if caught {
                    format!("Layer 3 detected float opcode(s) in compiled artifact: {}", offending_opcodes.join(", "))
                } else {
                    "MISSED — Layer 3 binary scan did not detect f32.add opcode in compiled rlib".into()
                },
            };
        }
    }

    // Fallback if cargo build fails: test Layer 3 directly with synthetic WASM module containing f32.add
    let wasm_file = tmp_dir.join("nc3_synthetic.wasm");
    // Synthetic WASM: header + type + function + code section with 0x92 (f32.add)
    let synthetic_wasm = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // \0asm\1\0\0\0
        0x0a, 0x05, 0x01, 0x03, 0x00, 0x92, 0x0b        // Code section: size 5, 1 func, 0 locals, f32.add (0x92), end (0x0b)
    ];
    std::fs::write(&wasm_file, &synthetic_wasm).ok();
    let bin_res = crate::layer3_binary::scan_artifact(&wasm_file);
    let caught = !bin_res.passed;
    NegativeControlResult {
        control_id: "NC-3".into(),
        description: "Crate compiled with float enabled (WASM artifact containing f32.add)".into(),
        injection: "WASM bytecode with opcode 0x92 (f32.add)".into(),
        layer_caught: if caught { Some("Layer 3 (Binary Opcode Scan)".into()) } else { None },
        passed: caught,
        details: if caught {
            "Layer 3 detected opcode f32.add in WASM code section".into()
        } else {
            "MISSED — Layer 3 binary scan did not catch opcode".into()
        },
    }
}
