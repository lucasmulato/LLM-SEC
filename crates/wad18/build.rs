// Build script for wad18 crate: Layer 1 AST/Token scanner enforcing zero floating-point.

use std::fs;
use std::path::Path;

fn scan_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
                for (line_no, line) in content.lines().enumerate() {
                    // Check for forbidden float keywords or types
                    let trimmed = line.trim();
                    // Ignore comment lines explaining the ban
                    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
                        continue;
                    }
                    if line.contains("f32") || line.contains("f64") {
                        panic!(
                            "PURE WAD18 Violation: Floating-point token detected in {}:{} -> '{}'",
                            path.display(),
                            line_no + 1,
                            trimmed
                        );
                    }
                }
            }
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src");
    let src_dir = Path::new("src");
    if src_dir.exists() {
        scan_dir(src_dir);
    }
}
