//! Offline Audit & Replay Tool: Recomputes cryptographic hash chain and detects tampering.

use std::env;
use std::process::exit;
use ssi_ledger::AppendOnlyLedgerStore;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: replay_audit <path-to-ledger.ndjson>");
        exit(2);
    }

    let ledger_path = &args[1];
    println!("[AUDIT] Starting offline cryptographic replay of: {ledger_path}");

    match AppendOnlyLedgerStore::with_file(ledger_path) {
        Ok(store) => match store.verify_integrity() {
            Ok(count) => {
                println!(
                    "[AUDIT_PASS] Verified {count} transitions. Root chain intact. Final hash: {}",
                    store.last_record_hash()
                );
                exit(0);
            }
            Err(e) => {
                eprintln!("[AUDIT_FAIL] Chain verification failed: {e}");
                exit(1);
            }
        },
        Err(e) => {
            eprintln!("[AUDIT_FAIL] Tampering / load error detected: {e}");
            exit(1);
        }
    }
}
