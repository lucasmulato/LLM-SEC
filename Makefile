# LLM-SEC Formally Verified Execution Gateway
# Automation Makefile conforming to AGENTS.md, PO-9, and Normative Requirements

.PHONY: all build pure-wad18 test tlc mutation replay domain sbom verify clean docker-build

all: build

build:
	cargo build --workspace --all-targets

pure-wad18:
	cargo run -p pure-wad18

test:
	cargo test --workspace

tlc:
	java -XX:+UseParallelGC -cp specs/tla/tla2tools.jar tlc2.TLC -config specs/tla/SSI_Kernel.cfg -workers 4 specs/tla/SSI_Kernel.tla

mutation:
	cargo run -p mutation_engine

replay:
	cargo run -p ssi-ledger --bin replay_audit tests/fixtures/audit_sample.ndjson

domain:
	bash packs/real-estate/run.sh

sbom:
	python3 scripts/generate_sbom.py

verify:
	python3 scripts/verify.py

clean:
	cargo clean
	rm -f tests/fixtures/audit_sample.ndjson
