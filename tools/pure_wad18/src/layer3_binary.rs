// PURE WAD-18 Verification Pipeline — Layer 3: Binary/Opcode Scanner

use std::path::Path;
use std::process::Command;
use crate::json::json_str;

#[derive(Debug, Clone)]
pub struct BinaryFinding {
    pub artifact: String,
    pub format: String,
    pub opcode: String,
    pub location: String,
}

impl BinaryFinding {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{ "artifact": {}, "format": {}, "opcode": {}, "location": {} }}"#,
            json_str(&self.artifact),
            json_str(&self.format),
            json_str(&self.opcode),
            json_str(&self.location),
        )
    }
}

#[derive(Debug, Clone)]
pub struct BinaryResult {
    pub passed: bool,
    pub artifacts_scanned: Vec<String>,
    pub findings: Vec<BinaryFinding>,
}

/// WASM code-section float opcodes (byte -> name)
/// Complete set from WebAssembly Core Specification §5.4.6
const WASM_FLOAT_OPCODES: &[(u8, &str)] = &[
    (0x43, "f32.const"), (0x44, "f64.const"),
    (0x2A, "f32.load"), (0x2B, "f64.load"),
    (0x38, "f32.store"), (0x39, "f64.store"),
    (0x5B, "f32.eq"), (0x61, "f64.eq"),
    (0x5C, "f32.ne"), (0x62, "f64.ne"),
    (0x5D, "f32.lt"), (0x63, "f64.lt"),
    (0x5E, "f32.gt"), (0x64, "f64.gt"),
    (0x5F, "f32.le"), (0x65, "f64.le"),
    (0x60, "f32.ge"), (0x66, "f64.ge"),
    (0x8B, "f32.abs"), (0x99, "f64.abs"),
    (0x8C, "f32.neg"), (0x9A, "f64.neg"),
    (0x8D, "f32.ceil"), (0x9B, "f64.ceil"),
    (0x8E, "f32.floor"), (0x9C, "f64.floor"),
    (0x8F, "f32.trunc"), (0x9D, "f64.trunc"),
    (0x90, "f32.nearest"), (0x9E, "f64.nearest"),
    (0x91, "f32.sqrt"), (0x9F, "f64.sqrt"),
    (0x92, "f32.add"), (0xA0, "f64.add"),
    (0x93, "f32.sub"), (0xA1, "f64.sub"),
    (0x94, "f32.mul"), (0xA2, "f64.mul"),
    (0x95, "f32.div"), (0xA3, "f64.div"),
    (0x96, "f32.min"), (0xA4, "f64.min"),
    (0x97, "f32.max"), (0xA5, "f64.max"),
    (0x98, "f32.copysign"), (0xA6, "f64.copysign"),
    (0xA8, "i32.trunc_f32_s"), (0xA9, "i32.trunc_f32_u"),
    (0xAA, "i32.trunc_f64_s"), (0xAB, "i32.trunc_f64_u"),
    (0xAE, "i64.trunc_f32_s"), (0xAF, "i64.trunc_f32_u"),
    (0xB0, "i64.trunc_f64_s"), (0xB1, "i64.trunc_f64_u"),
    (0xB2, "f32.convert_i32_s"), (0xB3, "f32.convert_i32_u"),
    (0xB4, "f32.convert_i64_s"), (0xB5, "f32.convert_i64_u"),
    (0xB6, "f32.demote_f64"), (0xB7, "f64.convert_i32_s"),
    (0xB8, "f64.convert_i32_u"), (0xB9, "f64.convert_i64_s"),
    (0xBA, "f64.convert_i64_u"), (0xBB, "f64.promote_f32"),
    (0xBC, "i32.reinterpret_f32"), (0xBD, "i64.reinterpret_f64"),
    (0xBE, "f32.reinterpret_i32"), (0xBF, "f64.reinterpret_i64"),
];

/// ELF objdump FP mnemonic substrings
const ELF_FP_MNEMONICS: &[&str] = &[
    "addsd", "addss", "addpd", "addps",
    "subsd", "subss", "subpd", "subps",
    "mulsd", "mulss", "mulpd", "mulps",
    "divsd", "divss", "divpd", "divps",
    "vmovsd", "vmovss", "movsd", "movss",
    "cvtsi2sd", "cvtsi2ss", "cvtss2sd", "cvtsd2ss",
    "ucomisd", "ucomiss", "comisd", "comiss",
    "sqrtsd", "sqrtss",
    "fadd", "fmul", "fdiv", "fsub", "fld", "fstp",
    "vadd", "vmul", "vdiv", "vsub",
];

pub fn scan_artifacts(artifacts: &[String]) -> BinaryResult {
    let mut all_findings = Vec::new();
    let mut all_scanned = Vec::new();
    for artifact in artifacts {
        let path = Path::new(artifact);
        if path.exists() {
            let r = scan_artifact(path);
            all_findings.extend(r.findings);
            all_scanned.extend(r.artifacts_scanned);
        }
    }
    BinaryResult {
        passed: all_findings.is_empty(),
        artifacts_scanned: all_scanned,
        findings: all_findings,
    }
}

pub fn scan_artifact(path: &Path) -> BinaryResult {
    let path_str = path.to_string_lossy().to_string();
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return err_result(path_str, "unknown", &format!("IO_ERROR: {}", e)),
    };

    if data.starts_with(b"!<arch>\n") {
        scan_ar_archive(&data, &path_str)
    } else if data.starts_with(b"\x00asm") {
        scan_wasm_bytes(&data, &path_str, "wasm")
    } else if data.starts_with(b"\x7fELF") {
        scan_elf(path, path_str)
    } else {
        scan_elf(path, path_str)
    }
}

fn scan_ar_archive(data: &[u8], path_str: &str) -> BinaryResult {
    let mut findings = Vec::new();
    let mut pos = 8;
    let opcode_map: std::collections::HashMap<u8, &str> =
        WASM_FLOAT_OPCODES.iter().map(|(b, n)| (*b, *n)).collect();

    while pos < data.len() {
        if pos + 60 > data.len() { break; }
        let header = &data[pos..pos+60];
        let name_raw = std::str::from_utf8(&header[0..16]).unwrap_or("").trim();
        let size_str = std::str::from_utf8(&header[48..58]).unwrap_or("0").trim();
        let size = size_str.parse::<usize>().unwrap_or(0);
        pos += 60;

        if pos + size > data.len() { break; }
        let member_data = &data[pos..pos+size];

        // Skip rust metadata objects (lib.rmeta, etc.) and symbol tables (/ or //)
        // Focus on actual code object members (*.rcgu.o, /0, etc.)
        if !name_raw.starts_with("lib.rmeta") && !name_raw.starts_with('/') {
            if member_data.starts_with(b"\x00asm") {
                let code_bytes = extract_code_section(member_data);
                for (offset, &byte) in code_bytes.iter().enumerate() {
                    if let Some(&name) = opcode_map.get(&byte) {
                        findings.push(BinaryFinding {
                            artifact: path_str.to_string(),
                            format: "wasm".to_string(),
                            opcode: name.to_string(),
                            location: format!("{}!code_section+0x{:04X}", name_raw, offset),
                        });
                    }
                }
            }
        }

        pos += size + (size % 2);
    }

    BinaryResult {
        passed: findings.is_empty(),
        artifacts_scanned: vec![path_str.to_string()],
        findings,
    }
}

pub fn scan_wasm_bytes(data: &[u8], path_str: &str, format_label: &str) -> BinaryResult {
    if data.len() < 8 || !data.starts_with(b"\x00asm") {
        return err_result(path_str.to_string(), format_label, "NOT_WASM: invalid magic bytes");
    }
    let opcode_map: std::collections::HashMap<u8, &str> =
        WASM_FLOAT_OPCODES.iter().map(|(b, n)| (*b, *n)).collect();
    let code_bytes = extract_code_section(data);
    let mut findings = Vec::new();
    for (offset, &byte) in code_bytes.iter().enumerate() {
        if let Some(&name) = opcode_map.get(&byte) {
            findings.push(BinaryFinding {
                artifact: path_str.to_string(),
                format: "wasm".to_string(),
                opcode: name.to_string(),
                location: format!("code_section+0x{:04X}", offset),
            });
        }
    }
    BinaryResult {
        passed: findings.is_empty(),
        artifacts_scanned: vec![path_str.to_string()],
        findings,
    }
}

fn extract_code_section(data: &[u8]) -> Vec<u8> {
    let mut pos = 8usize;
    let mut code = Vec::new();
    while pos < data.len() {
        let id = data[pos]; pos += 1;
        let (size, consumed) = read_leb128(&data[pos..]);
        pos += consumed;
        let end = pos + size as usize;
        if end > data.len() { break; }
        if id == 0x0A { code.extend_from_slice(&data[pos..end]); }
        pos = end;
    }
    code
}

fn read_leb128(data: &[u8]) -> (u32, usize) {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut pos = 0;
    loop {
        if pos >= data.len() { break; }
        let b = data[pos]; pos += 1;
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 { break; }
        shift += 7;
        if shift >= 32 { break; }
    }
    (result, pos)
}

fn scan_elf(path: &Path, path_str: String) -> BinaryResult {
    let output = Command::new("objdump")
        .args(["-d", "--no-show-raw-insn"])
        .arg(path)
        .output();
    match output {
        Ok(out) => {
            let disasm = String::from_utf8_lossy(&out.stdout);
            let mut findings = Vec::new();
            for (lineno, line) in disasm.lines().enumerate() {
                let lower = line.to_lowercase();
                for mnemonic in ELF_FP_MNEMONICS {
                    if lower.contains(mnemonic) {
                        let parts: Vec<&str> = line.splitn(3, '\t').collect();
                        let mnem_field = parts.get(1).unwrap_or(&"");
                        if mnem_field.to_lowercase().trim_start().starts_with(mnemonic) {
                            findings.push(BinaryFinding {
                                artifact: path_str.clone(),
                                format: "elf".to_string(),
                                opcode: mnemonic.to_string(),
                                location: format!("line {}: {}", lineno + 1, line.trim()),
                            });
                        }
                    }
                }
            }
            BinaryResult {
                passed: findings.is_empty(),
                artifacts_scanned: vec![path_str],
                findings,
            }
        }
        Err(e) => err_result(path_str, "elf", &format!("OBJDUMP_ERROR: {}", e)),
    }
}

fn err_result(artifact: String, format: &str, msg: &str) -> BinaryResult {
    BinaryResult {
        passed: false,
        artifacts_scanned: vec![artifact.clone()],
        findings: vec![BinaryFinding {
            artifact,
            format: format.to_string(),
            opcode: "SCAN_ERROR".to_string(),
            location: msg.to_string(),
        }],
    }
}
