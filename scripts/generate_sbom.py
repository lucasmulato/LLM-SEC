#!/usr/bin/env python3
"""Generates a CycloneDX-compatible JSON Software Bill of Materials (SBOM) from Cargo.lock."""

import json
import os
import hashlib

def parse_cargo_lock():
    lockfile_path = os.path.join(os.path.dirname(__file__), "..", "Cargo.lock")
    packages = []
    current_pkg = {}
    
    with open(lockfile_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "[[package]]":
                if current_pkg and "name" in current_pkg:
                    packages.append(current_pkg)
                current_pkg = {}
            elif "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"')
                if key in ("name", "version", "source", "checksum"):
                    current_pkg[key] = val
                    
        if current_pkg and "name" in current_pkg:
            packages.append(current_pkg)
            
    return packages

def generate_sbom():
    packages = parse_cargo_lock()
    components = []
    
    for p in packages:
        comp = {
            "type": "library",
            "name": p.get("name"),
            "version": p.get("version"),
            "purl": f"pkg:cargo/{p.get('name')}@{p.get('version')}",
            "scope": "required" if "source" in p else "internal"
        }
        if "checksum" in p:
            comp["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
        components.append(comp)
        
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:llm-sec-v0.1.0-sbom",
        "version": 1,
        "metadata": {
            "timestamp": "2026-11-11T12:00:00Z",
            "tools": [{"vendor": "LLM-SEC", "name": "generate_sbom.py", "version": "0.1.0"}],
            "component": {
                "type": "application",
                "name": "llm-sec",
                "version": "0.1.0",
                "description": "Safe Super Intelligence (SSI) Normative Execution Gateway"
            }
        },
        "components": components
    }
    
    out_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "sbom.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
        
    print(f"Generated SBOM at {out_path} with {len(components)} components.")

if __name__ == "__main__":
    generate_sbom()
