# AGENTS.md: Persistent Architectural and Operational Rules

> **Target Audience:** All AI agents, contributors, and automated tooling operating within the `LLM-SEC` repository.  
> **Authority:** Non-bypassable governance rules. All pull requests, code edits, and planning actions must strictly conform.

---

## 1. Core Engineering & Formal Verification Rules

### Rule 1: Fail-Closed Everywhere
- Any indeterminate state, evaluation timeout, parsing failure, or unhandled condition **MUST resolve to hard failure / rejection / quarantine**.
- $\text{Unknown} \neq \text{Safe}$. $\text{Unknown} \equiv \text{REJECT}$.
- An empty invariant set $\Phi = \emptyset$ is **never safe**: $\text{VS}(X) \equiv 0$.
- Any attempt to bypass, weaken, or omit an authorization or invariant check must abort execution immediately.

### Rule 2: Zero Floating-Point in Kernel (PURE WAD-18)
- Absolutely **no `f32`, `f64`, or floating-point literals** are allowed in kernel crates/modules.
- No float-casting or float-converting utility functions (`from_float`, `to_float`, `as_float`).
- Arithmetic must use 18-decimal fixed-point scaled integers (`WAD-18`, $10^{18}$) over 256-bit signed integers with explicit bounds checks.
- Enforced continuously via three independent layers:
  1. AST and source linter (`cargo clippy` with float-forbidding lints, custom AST scanners).
  2. Constrained compilation target (`no-std` / soft-float / WASM).
  3. Binary opcode scanning of the compiled artifact for floating-point instructions (`addsd`, `mulsd`, `f32.*`, etc.).

### Rule 3: Honest Conformance & Evidence Discipline
- **NEVER** label any property, module, or test as "proven", "verified", or "formally verified" without a machine-checked proof artifact.
- Unit tests (`unittest`, `pytest`, `cargo test`) and integration tests are **Level 1 (Executable)**.
- Bounded model checking (e.g., TLC run to depth $N$) must be explicitly documented as **Bounded Model Checking**, not an inductive mathematical proof.
- Proof claims require checking by an independent verifier (e.g., TLC complete state space exploration, Lean 4 proof certificates, Coq proof objects, or Z3 proofs).
- Every claim in documentation, PRs, and tables must cite its Conformance Level (`CONF-0` through `CONF-4`) alongside a link to the verifying artifact.

### Rule 4: Preserve the Python Prototype as Differential Oracle
- Do **NOT** delete or decommission the original Python implementation (`core/`, `tests/`).
- The Python code serves as an executable reference oracle for differential property-based testing against the formally verified Rust kernel.
- Any behavioral discrepancy between the Rust kernel and Python prototype must be traced to either a documented bug in the Python prototype or a formal specification refinement.

### Rule 5: Traceability to Proof Obligations (PO-1 through PO-9)
- Every pull request, task, and architectural refactoring must explicitly map to at least one Proof Obligation:
  - **PO-1:** Type Safety & State Inhabitance
  - **PO-2:** WAD-18 Arithmetic Soundness & Overflow Containment
  - **PO-3:** Authorization Soundness ($\neg\text{AUTH} \implies \neg\text{EXECUTE}$)
  - **PO-4:** Verification Soundness ($\neg\text{VER} \implies \neg\text{EXECUTE}$)
  - **PO-5:** Invariant Preservation ($\text{Next}(X,a,X') \implies \text{VS}(X')$)
  - **PO-6:** Cryptographic Lineage & State Identification
  - **PO-7:** Safety Kernel Immutability & Supremacy
  - **PO-8:** Recursive Non-Regression ($R^3$ / $\text{ADOPT}$)
  - **PO-9:** Deterministic Reproducibility & Audit Replay
- Every PR must update the conformance matrix in `docs/CONFORMANCE.md` or `README.md`.

### Rule 6: Spec-First Development Workflow
- Code never leads; specification always leads.
- Before modifying or implementing kernel logic:
  1. Update the Normative Specification in `docs/REQUIREMENTS.md`.
  2. Update the formal model (TLA+ specification in `specs/tla/`).
  3. Verify the updated model via TLC / model checkers.
  4. Only then implement and modify the Rust kernel code.

---

## 2. Operational & Context Budget Efficiency

*(Carried forward and aligned from `.agents/rules.md`)*

### 2.1 Token Saving Rules (Strict Context Budget)
- **Compact Responses:** Do not repeat the prompt, echo entire file contents, or write superfluous conversational filler. Deliver targeted changes and structured planning artifacts directly.
- **Diff-Only Code Outputs:** When modifying existing files, produce line-level diffs or targeted code replacements instead of re-printing 500+ line files.
- **Targeted File Inspection:** Inspect specific line ranges or grep pattern matches instead of reading whole trees into context.
- **Batch Tool Calls:** Execute related file inspections, terminal commands, or branch operations in a single batched step whenever possible.

### 2.2 Work Quality & Reliability Gates
- **Zero Hallucination:** Rely strictly on verified local repository code, formal mathematical specifications, and declared dependencies. Do not invent unverified API methods or theoretical proof claims.
- **Fail-Fast Validation:** Run linters, type checks, or unit tests immediately after every file modification to catch errors instantly.
- **Modular Boundaries:** Enforce absolute module separation between the immutable kernel $K$, mutable agents/models $M$, and governed configuration $G$.
- **Clean Git State:** Work in isolated feature branches or Git worktrees to maintain a clean git history and fast rollbacks.
