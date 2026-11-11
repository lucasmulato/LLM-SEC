//! CSL Signer CLI: Key generation, CSL envelope signing, and dual approval creation.

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use ssi_real_estate::{
    DualHumanApproval, UnderwritingTier, create_underwriting_csl_envelope,
};
use wad18::Wad18;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "generate-key" => {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let priv_hex = hex::encode(signing_key.to_bytes());
            let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
            println!("Generated Human Underwriter Keypair:");
            println!("  Private Key (Hex): {}", priv_hex);
            println!("  Public Key (Hex):  {}", pub_hex);
        }
        "sign-envelope" => {
            let auth_id = args.get(2).map(|s| s.as_str()).unwrap_or("auth-underwriter-001");
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

            let csl = create_underwriting_csl_envelope(
                &signing_key,
                auth_id,
                UnderwritingTier::Tier2Standard,
                1000,
                100_000,
                500,
            );

            println!("Signed CSL Underwriting Envelope:");
            println!("  Auth ID:       {}", csl.auth_id);
            println!("  Signatory Pub: {}", pub_hex);
            println!("  Signature:     {}", hex::encode(csl.signature.to_bytes()));
            println!("  Max Risk:      {} WAD", csl.envelope.max_risk_bound);
            println!("  Budget Limit:  {} WAD", csl.envelope.total_budget_limit);
            println!("  Constraints:   {:?}", csl.constraints);
        }
        "sign-dual-approval" => {
            let app_id = args.get(2).map(|s| s.as_str()).unwrap_or("app-comm-999");
            let loan_amount: i128 = args
                .get(3)
                .and_then(|s| s.parse().ok())
                .unwrap_or(2_500_000_000_000_000_000_000_000); // $2.5M
            let epoch: i64 = 2000;

            let mut csprng = OsRng;
            let senior_key = SigningKey::generate(&mut csprng);
            let chair_key = SigningKey::generate(&mut csprng);

            let digest = DualHumanApproval::canonical_digest_bytes(app_id, loan_amount, epoch);
            let sig_senior = senior_key.sign(&digest);
            let sig_chair = chair_key.sign(&digest);

            let approval = DualHumanApproval {
                senior_underwriter_pubkey: senior_key.verifying_key().to_bytes(),
                senior_underwriter_sig: sig_senior.to_bytes(),
                risk_chair_pubkey: chair_key.verifying_key().to_bytes(),
                risk_chair_sig: sig_chair.to_bytes(),
                approval_epoch: epoch,
            };

            assert!(approval.verify(app_id, loan_amount).is_ok());

            println!("Created Dual Human Approval for High-Value Loan:");
            println!("  Application ID:         {}", app_id);
            println!("  Loan Amount:            {} WAD", Wad18::from_raw(loan_amount));
            println!("  Senior Underwriter Pub: {}", hex::encode(approval.senior_underwriter_pubkey));
            println!("  Risk Chair Pub:         {}", hex::encode(approval.risk_chair_pubkey));
            println!("  Signatures Verified:    SUCCESS");
        }
        _ => {
            println!("SSI Real-Estate CSL Signer Utility");
            println!("Usage: csl_signer <command> [args]");
            println!("Commands:");
            println!("  generate-key");
            println!("  sign-envelope [auth_id]");
            println!("  sign-dual-approval [app_id] [loan_amount_wad]");
        }
    }
}
