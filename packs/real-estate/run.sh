#!/usr/bin/env bash
# One-command reproducible runner: demo + red-team + tests
# Phase 4a acceptance gate (Russell 2026 / AGENTS.md Rule 1)
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "========================================================"
echo " SSI Real-Estate Pack — Phase 4a Acceptance Run"
echo "========================================================"

echo ""
echo "[1/3] Demo: LLM-Agent Underwriting Pipeline"
cargo run -p ssi-real-estate --bin re_demo

echo ""
echo "[2/3] Red-Team: 6 Adversarial Attack Vectors"
cargo run -p ssi-real-estate --bin re_redteam

echo ""
echo "[3/3] Integration Test Suite"
cargo test -p ssi-real-estate --test re_tests -- --test-threads=1

echo ""
echo "========================================================"
echo " ACCEPTANCE: Demo passed | 6/6 attacks caught | tests OK"
echo "========================================================"
