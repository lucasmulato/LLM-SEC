// PURE WAD-18 Verification Pipeline — Report Generator (no-dep JSON + Markdown)

use std::path::Path;
use crate::json::json_str;
use crate::layer1_source::SourceFinding;
use crate::layer2_build::BuildResult;
use crate::layer3_binary::BinaryResult;
use crate::negative_controls::NegativeControlResult;

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict { VERIFIED, FAIL }

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Verdict::VERIFIED => write!(f, "VERIFIED"), Verdict::FAIL => write!(f, "FAIL") }
    }
}

pub fn write_reports(
    scope: &str,
    timestamp: &str,
    files_scanned: usize,
    l1_findings: &[SourceFinding],
    build: &BuildResult,
    binary: &BinaryResult,
    controls: &[NegativeControlResult],
    md_path: &Path,
    json_path: &Path,
) -> Verdict {
    let l1_pass = l1_findings.is_empty();
    let l2_pass = build.passed;
    let l3_pass = binary.passed;
    let nc_pass = controls.iter().all(|c| c.passed);
    let verdict = if l1_pass && l2_pass && l3_pass { Verdict::VERIFIED } else { Verdict::FAIL };

    // JSON
    let l1_jsons: Vec<String> = l1_findings.iter().map(|f| f.to_json()).collect();
    let bf_jsons: Vec<String> = binary.findings.iter().map(|f| f.to_json()).collect();
    let nc_jsons: Vec<String> = controls.iter().map(|c| c.to_json()).collect();
    let art_scanned: Vec<String> = binary.artifacts_scanned.iter().map(|s| json_str(s)).collect();
    let _art_built: Vec<String> = build.artifacts.iter().map(|s| json_str(s)).collect();

    let json = format!(
        r#"{{
  "schema_version": "1.0",
  "tool": "pure-wad18",
  "timestamp": {},
  "scope": {},
  "verdict": {},
  "scope_disclaimer": "Conformance to the PURE WAD-18 verification procedure for the named artifacts at the given timestamp. NOT a proof of all behaviors; Conformance Level 2 (Reproducible).",
  "layer1_source": {{
    "passed": {},
    "files_scanned": {},
    "findings_count": {},
    "findings": [{}]
  }},
  "layer2_build": {},
  "layer3_binary": {{
    "passed": {},
    "artifacts_scanned": [{}],
    "findings_count": {},
    "findings": [{}]
  }},
  "negative_controls": [{}],
  "negative_controls_all_caught": {}
}}"#,
        json_str(timestamp),
        json_str(scope),
        json_str(&verdict.to_string()),
        l1_pass,
        files_scanned,
        l1_findings.len(),
        l1_jsons.join(",\n    "),
        build.to_json(),
        l3_pass,
        art_scanned.join(", "),
        binary.findings.len(),
        bf_jsons.join(",\n    "),
        nc_jsons.join(",\n  "),
        nc_pass,
    );
    std::fs::write(json_path, &json).ok();

    // Markdown
    let mut md = String::new();
    md.push_str("# PURE WAD-18 Verification Report\n\n");
    md.push_str(&format!("> **Generated:** {}  \n> **Tool:** `pure-wad18`  \n> **Scope:** `{}`\n\n", timestamp, scope));
    let badge = if verdict == Verdict::VERIFIED { "✅ **VERDICT: VERIFIED**" } else { "❌ **VERDICT: FAIL**" };
    md.push_str(&format!("## {}\n\n", badge));

    md.push_str("## Layer Summary\n\n");
    md.push_str("| Layer | Description | Result |\n|-------|-------------|--------|\n");
    md.push_str(&format!("| **Layer 1** | Source scanner — {} files scanned | {} |\n", files_scanned,
        if l1_pass { "✅ PASS" } else { "❌ FAIL" }));
    md.push_str(&format!("| **Layer 2** | Float-free build (`{}`) | {} |\n", build.target,
        if l2_pass { "✅ PASS" } else { "❌ FAIL" }));
    md.push_str(&format!("| **Layer 3** | Binary opcode scan — {} artifact(s) | {} |\n\n",
        binary.artifacts_scanned.len(), if l3_pass { "✅ PASS" } else { "❌ FAIL" }));

    // Layer 1
    md.push_str("## Layer 1: Source Scan\n\n");
    if l1_findings.is_empty() {
        md.push_str("**Result:** No float tokens found in kernel sources.\n\n");
    } else {
        md.push_str(&format!("**Result:** {} finding(s):\n\n", l1_findings.len()));
        md.push_str("| File | Line | Col | Token | Context |\n|------|------|-----|-------|---------|\n");
        for f in l1_findings {
            md.push_str(&format!("| `{}` | {} | {} | `{}` | `{}` |\n",
                Path::new(&f.file).file_name().unwrap_or_default().to_string_lossy(),
                f.line, f.column, f.token,
                f.context.replace('|', "\\|").chars().take(60).collect::<String>()));
        }
        md.push('\n');
    }

    // Layer 2
    md.push_str("## Layer 2: Float-Free Build\n\n");
    md.push_str(&format!("**Target:** `{}`\n\n**Justification:** {}\n\n", build.target, build.target_justification));
    if l2_pass {
        md.push_str("**Result:** Build succeeded; zero float-related compiler errors.\n\n");
    } else {
        md.push_str("**Result:** Build FAILED or emitted errors:\n\n```\n");
        for line in &build.error_lines { md.push_str(line); md.push('\n'); }
        md.push_str("```\n\n");
    }
    if !build.artifacts.is_empty() {
        md.push_str("**Artifacts produced:**\n");
        for a in &build.artifacts { md.push_str(&format!("- `{}`\n", a)); }
        md.push('\n');
    }

    // Layer 3
    md.push_str("## Layer 3: Binary Opcode Scan\n\n");
    if binary.artifacts_scanned.is_empty() {
        md.push_str("**Warning:** No artifacts available to scan (Layer 2 may have failed).\n\n");
    } else {
        md.push_str("**Artifacts scanned:**\n");
        for a in &binary.artifacts_scanned { md.push_str(&format!("- `{}`\n", a)); }
        md.push('\n');
        if binary.findings.is_empty() {
            md.push_str("**Result:** Zero float/vector opcodes detected.\n\n");
        } else {
            md.push_str(&format!("**Result:** {} opcode(s) detected:\n\n", binary.findings.len()));
            md.push_str("| Artifact | Format | Opcode | Location |\n|----------|--------|--------|----------|\n");
            for f in &binary.findings {
                md.push_str(&format!("| `{}` | {} | `{}` | `{}` |\n",
                    Path::new(&f.artifact).file_name().unwrap_or_default().to_string_lossy(),
                    f.format, f.opcode, f.location.chars().take(80).collect::<String>()));
            }
            md.push('\n');
        }
    }

    // Negative Controls
    md.push_str("## Negative Controls\n\nAll three must be CAUGHT for pipeline sensitivity to be valid.\n\n");
    md.push_str("| ID | Description | Layer Caught | Result |\n|----|-------------|-------------|--------|\n");
    for c in controls {
        md.push_str(&format!("| {} | {} | {} | {} |\n",
            c.control_id, c.description,
            c.layer_caught.as_deref().unwrap_or("NONE — NOT CAUGHT"),
            if c.passed { "✅ CAUGHT" } else { "❌ MISSED" }));
    }
    md.push('\n');
    if nc_pass {
        md.push_str("**All negative controls caught. Pipeline sensitivity validated.**\n\n");
    } else {
        md.push_str("**⚠️ WARNING: Negative control(s) missed — pipeline sensitivity INVALID.**\n\n");
    }

    // Scope
    md.push_str("---\n\n## Scope & Conformance\n\n");
    md.push_str("> [!NOTE]\n> This report certifies **conformance to the specified PURE WAD-18 verification procedure** \
        for the named source tree and binary artifacts at the stated timestamp. \
        It is NOT a proof of all behaviors of the software; it does not constitute a formal \
        mathematical proof of zero floating-point in all possible compilations or configurations.\n\n");
    md.push_str("**Conformance Level:** 2 (Reproducible) — procedure documented, artifacts pinned, \
        reproducible by an independent executor following the same procedure.  \n");
    md.push_str("**Conformance Level 3** (Mechanically Verified) requires a TLA+/TLC or Lean 4 proof artifact (Phase 2).\n");

    std::fs::write(md_path, md).ok();
    verdict
}
