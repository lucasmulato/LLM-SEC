// PURE WAD-18 Verification Pipeline — Layer 1: Source Scanner
//
// Scans Rust source files (after stripping line/block comments and string literals)
// for forbidden float-related tokens.

use std::path::Path;
use crate::json::json_str;

#[derive(Debug, Clone)]
pub struct SourceFinding {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub token: String,
    pub context: String,
}

impl SourceFinding {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{ "file": {}, "line": {}, "column": {}, "token": {}, "context": {} }}"#,
            json_str(&self.file),
            self.line,
            self.column,
            json_str(&self.token),
            json_str(&self.context),
        )
    }
}

/// Strip line/block comments and string/char literals from source.
/// Preserves newlines so line numbers remain accurate.
fn strip_comments_and_strings(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0;

    while i < n {
        // Line comment
        if i + 1 < n && chars[i] == '/' && chars[i + 1] == '/' {
            while i < n && chars[i] != '\n' { out.push(' '); i += 1; }
            continue;
        }
        // Block comment
        if i + 1 < n && chars[i] == '/' && chars[i + 1] == '*' {
            out.push(' '); out.push(' '); i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' { out.push('\n'); } else { out.push(' '); }
                i += 1;
            }
            if i + 1 < n { out.push(' '); out.push(' '); i += 2; }
            continue;
        }
        // Raw string r#"..."# (various hash depths)
        if chars[i] == 'r' {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while j < n && chars[j] == '#' { hashes += 1; j += 1; }
            if j < n && chars[j] == '"' {
                out.push(' '); i = j + 1;
                loop {
                    if i >= n { break; }
                    if chars[i] == '"' {
                        let mut k = i + 1; let mut ch = 0;
                        while k < n && chars[k] == '#' && ch < hashes { ch += 1; k += 1; }
                        if ch == hashes { out.push(' '); i = k; break; }
                    }
                    if chars[i] == '\n' { out.push('\n'); } else { out.push(' '); }
                    i += 1;
                }
                continue;
            }
        }
        // String literal
        if chars[i] == '"' {
            out.push(' '); i += 1;
            while i < n {
                if chars[i] == '\\' { out.push(' '); out.push(' '); i += 2; continue; }
                if chars[i] == '"' { out.push(' '); i += 1; break; }
                if chars[i] == '\n' { out.push('\n'); } else { out.push(' '); }
                i += 1;
            }
            continue;
        }
        // Char literal
        if chars[i] == '\'' {
            out.push(' '); i += 1;
            while i < n {
                if chars[i] == '\\' { out.push(' '); out.push(' '); i += 2; continue; }
                if chars[i] == '\'' { out.push(' '); i += 1; break; }
                out.push(' '); i += 1;
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out.iter().collect()
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_float_tokens(cleaned: &str) -> Vec<(usize, usize, String)> {
    let mut findings = Vec::new();
    let bytes = cleaned.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        // f32 / f64 as standalone identifiers
        for kw in &["f32", "f64"] {
            let klen = kw.len();
            if i + klen <= n && &cleaned[i..i+klen] == *kw {
                let before_ok = i == 0 || !is_ident_char(bytes[i - 1]);
                let after_ok = i + klen >= n || !is_ident_char(bytes[i + klen]);
                if before_ok && after_ok {
                    findings.push((i, klen, kw.to_string()));
                }
            }
        }
        // std::f32 / std::f64 / core::f32 / core::f64
        for prefix in &["std::f32", "std::f64", "core::f32", "core::f64"] {
            let plen = prefix.len();
            if i + plen <= n && &cleaned[i..i+plen] == *prefix {
                let before_ok = i == 0 || !is_ident_char(bytes[i - 1]);
                if before_ok {
                    findings.push((i, plen, prefix.to_string()));
                }
            }
        }
        // Float literal: digits . digits (not ..)
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < n && bytes[j].is_ascii_digit() { j += 1; }

            // digits.digits pattern (float literal)
            if j < n && bytes[j] == b'.' && j + 1 < n && bytes[j+1] != b'.' && !bytes[j+1].is_ascii_alphabetic() {
                j += 1;
                while j < n && (bytes[j].is_ascii_digit() || bytes[j] == b'_') { j += 1; }
                // optional exponent
                if j < n && (bytes[j] == b'e' || bytes[j] == b'E') {
                    let ej = j; j += 1;
                    if j < n && (bytes[j] == b'+' || bytes[j] == b'-') { j += 1; }
                    if j < n && bytes[j].is_ascii_digit() {
                        while j < n && bytes[j].is_ascii_digit() { j += 1; }
                    } else { j = ej; }
                }
                // optional f32/f64 suffix
                for suf in &["f32", "f64"] {
                    if j + suf.len() <= n && &cleaned[j..j+suf.len()] == *suf { j += suf.len(); break; }
                }
                findings.push((start, j - start, cleaned[start..j].to_string()));
                i = j; continue;
            }
            // digits with f32/f64 suffix (e.g. 42f64)
            let mut advanced = false;
            for suf in &["f32", "f64"] {
                let slen = suf.len();
                if j + slen <= n && &cleaned[j..j+slen] == *suf {
                    let after_ok = j + slen >= n || !is_ident_char(bytes[j + slen]);
                    if after_ok {
                        findings.push((start, j+slen-start, cleaned[start..j+slen].to_string()));
                        i = j + slen; advanced = true; break;
                    }
                }
            }
            if advanced { continue; }
            // exponent-only: digits e/E sign? digits (e.g. 1e5) — indicates float context
            if j < n && (bytes[j] == b'e' || bytes[j] == b'E') {
                let _ej = j; j += 1;
                if j < n && (bytes[j] == b'+' || bytes[j] == b'-') { j += 1; }
                if j < n && bytes[j].is_ascii_digit() {
                    while j < n && bytes[j].is_ascii_digit() { j += 1; }
                    findings.push((start, j - start, cleaned[start..j].to_string()));
                    i = j; continue;
                }
                // not a valid exponent — fall through
            }
        }
        i += 1;
    }
    findings
}

fn byte_to_line_col(text: &str, byte_off: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut last_newline = 0usize;
    for (i, c) in text.char_indices() {
        if i >= byte_off { break; }
        if c == '\n' { line += 1; last_newline = i + 1; }
    }
    (line, byte_off - last_newline + 1)
}

pub fn scan_file(path: &Path) -> Vec<SourceFinding> {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let cleaned = strip_comments_and_strings(&src);
    let raw_findings = find_float_tokens(&cleaned);
    let lines: Vec<&str> = src.lines().collect();
    let mut findings = Vec::new();
    for (byte_off, _len, token) in raw_findings {
        let (line_no, col) = byte_to_line_col(&cleaned, byte_off);
        let context = lines.get(line_no.saturating_sub(1)).unwrap_or(&"").trim().to_string();
        findings.push(SourceFinding {
            file: path.to_string_lossy().to_string(),
            line: line_no,
            column: col,
            token,
            context,
        });
    }
    findings
}

pub fn scan_crates_dir(dir: &Path) -> (usize, Vec<SourceFinding>) {
    let mut findings = Vec::new();
    let mut count = 0usize;
    scan_dir_recursive(dir, &mut findings, &mut count);
    (count, findings)
}

fn scan_dir_recursive(dir: &Path, findings: &mut Vec<SourceFinding>, count: &mut usize) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            if name != "target" && name != ".git" && name != ".pure_wad18_tmp" {
                scan_dir_recursive(&path, findings, count);
            }
        } else if path.is_file() {
            if path.extension().map(|e| e == "rs").unwrap_or(false) {
                *count += 1;
                findings.extend(scan_file(&path));
            }
        }
    }
}
