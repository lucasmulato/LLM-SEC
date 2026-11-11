# Mathematical Trace Refinement Mapping & Conformance Specification

> **Document Version:** 1.0.0  
> **Normative Reference:** [`docs/REQUIREMENTS.md`](../../docs/REQUIREMENTS.md), [`specs/tla/SSI_Kernel.tla`](SSI_Kernel.tla)  
> **Proof Obligations:** PO-3, PO-4, PO-5, PO-9  
> **Conformance Level:** Level 3 (Bounded Model Checking & Mechanized Trace Conformance)

---

## 1. Refinement Mapping Definition $\mathcal{M}$

Let $\mathcal{S}_{\text{Rust}}$ denote the domain of Rust gateway states `SystemState` ($X = (I, S, A, H, V, P)$), and let $\mathcal{S}_{\text{TLA}}$ denote the state record domain defined in `SSI_Kernel.tla`.

The refinement mapping $\mathcal{M}: \mathcal{S}_{\text{Rust}} \to \mathcal{S}_{\text{TLA}}$ is defined component-wise as:

$$\mathcal{M}(X) \triangleq [I \mapsto \mathcal{M}_I(X.I), S \mapsto \mathcal{M}_S(X.S), A \mapsto \mathcal{M}_A(X.A), H \mapsto \mathcal{M}_H(X.H), V \mapsto \mathcal{M}_V(X.V), P \mapsto \mathcal{M}_P(X.P), CSL \mapsto \mathcal{M}_{CSL}(X.S)]$$

### 1.1 Component Projections

1. **Intelligence ($\mathcal{M}_I$):**
   - $\text{budget} \triangleq \lfloor X.I.\text{cognitive\_budget} \rfloor$
   - $\text{epistemic\_confidence\_valid} \triangleq (0 \le X.I.\text{epistemic\_confidence} \le 10^{18})$
   - $\text{capabilities} \triangleq X.I.\text{capabilities}$

2. **Safety ($\mathcal{M}_S$):**
   - $\text{containment\_active} \triangleq X.S.\text{containment\_active}$
   - $\text{containment\_barrier\_intact} \triangleq X.S.\text{containment\_barrier\_intact}$
   - $\text{quarantine\_flag} \triangleq X.S.\text{quarantine\_flag}$
   - $\text{risk\_bound} \triangleq \lfloor X.S.\text{risk\_bound} \rfloor$
   - $\text{safety\_margin} \triangleq \lfloor X.S.\text{safety\_margin} \rfloor$
   - $\text{csl\_constraints} \triangleq X.S.\text{csl\_constraints}$

3. **Action Proposal ($\mathcal{M}_A$):**
   - $\text{id} \triangleq X.A.\text{action\_id}$
   - $\text{type} \triangleq X.A.\text{action\_type}$
   - $\text{risk} \triangleq \lfloor X.A.\text{risk\_assessment} \rfloor$
   - $\text{cost} \triangleq \lfloor X.A.\text{resource\_cost} \rfloor$
   - $\text{clearance} \triangleq X.A.\text{required\_clearance}$
   - $\text{payload\_digest\_valid} \triangleq (\text{len}(X.A.\text{payload\_digest}) = 64)$
   - $\text{is\_executed} \triangleq X.A.\text{is\_executed}$

4. **Authorization ($\mathcal{M}_H$):**
   - $\text{token\_valid} \triangleq (X.H.\text{auth\_token} \ne "")$
   - $\text{nonce\_valid} \triangleq (X.H.\text{nonce} \ne "")$
   - $\text{clearance} \triangleq X.H.\text{clearance\_level}$
   - $\text{is\_active} \triangleq X.H.\text{is\_active}$
   - $\text{expires\_at} \triangleq X.H.\text{expires\_at\_epoch}$

5. **Verification ($\mathcal{M}_V$):**
   - $\text{is\_valid} \triangleq X.V.\text{is\_valid}$
   - $\text{certificate\_valid} \triangleq (X.V.\text{certificate\_id} \ne "")$
   - $\text{verifier\_identity\_valid} \triangleq (X.V.\text{verifier\_identity} \ne "")$

6. **Provenance ($\mathcal{M}_P$):**
   - $\text{sequence\_number} \triangleq X.P.\text{sequence\_number}$
   - $\text{parent\_hash\_valid} \triangleq (X.P.\text{sequence\_number} = 0 \lor \text{len}(X.P.\text{parent\_state\_hash}) = 64)$
   - $\text{merkle\_root\_valid} \triangleq (\text{len}(X.P.\text{merkle\_root}) = 64)$
   - $\text{audit\_trail\_id\_valid} \triangleq (X.P.\text{audit\_trail\_id} \ne "")$

7. **CSL Operating Envelope ($\mathcal{M}_{CSL}$):**
   - $\text{revoked} \triangleq \text{False}$ (or explicit revocation message received)
   - $\text{envelope\_active} \triangleq (X.S.\text{active\_envelope\_id} \ne "")$
   - $\text{envelope\_exceeded} \triangleq (X.S.\text{quarantine\_flag} \lor X.S.\text{csl\_constraints} = \emptyset)$

---

## 2. Transition Conformance Theorems

For any recorded trace transition step $\sigma_k = \langle X_k, a_k, \text{epoch}_k, \text{ver\_status}_k, \text{decision}_k, X_{k+1}, \text{commit}_k \rangle$:

### Theorem 1 (Refinement Soundness)
If $\text{decision}_k = \text{Permit}$, then the mapped transition satisfies the TLA+ `EvaluateAndTransition` specification:
$$\mathcal{M}(X_k) \xrightarrow{\text{ActionStep}(a_k)} \mathcal{M}(X_{k+1})$$

### Theorem 2 (Permit Soundness — PO-3, PO-4)
$$\text{decision}_k = \text{Permit} \iff \text{PERMIT}(\mathcal{M}(X_k), \mathcal{M}_A(a_k), \text{ver\_status}_k, \text{epoch}_k)$$
Any execution where $\text{decision}_k = \text{Permit}$ but $\text{PERMIT} = \text{False}$ is a hard violation.

### Theorem 3 (Containment of Rejection — Zero External Effect)
$$\text{decision}_k = \text{Reject} \implies X_{k+1} = X_k \land \text{commit}_k = \text{None}$$

### Theorem 4 (Monotonic Progression — PO-5, PO-9)
$$\text{decision}_k = \text{Permit} \implies X_{k+1}.P.\text{sequence\_number} = X_k.P.\text{sequence\_number} + 1 \land X_{k+1}.I.\text{budget} \le X_k.I.\text{budget}$$

### Theorem 5 (Cryptographic Parent Integrity — PO-6)
$$\text{decision}_k = \text{Permit} \implies X_{k+1}.P.\text{parent\_state\_hash} = \text{SHA-256}(\text{ENC}(X_k))$$

---

## 3. Negative Control Matrix for Trace Validator

The runtime trace validator (`tools/trace-validator`) must detect and reject the following 6 canonical trace corruptions:

| Failure Code | Corruption Description | Expected Verdict |
| :--- | :--- | :---: |
| `TAMPER_PRE_STATE` | Modified field in $X_k$ after execution | **FAIL (REJECT)** |
| `TAMPER_POST_STATE` | Arbitrary modification of $X_{k+1}$ without cryptographic commitment | **FAIL (REJECT)** |
| `FORGED_PERMIT` | `decision = Permit` when credentials expired or insufficient clearance | **FAIL (REJECT)** |
| `NON_MONOTONIC_SEQ` | $X_{k+1}.\text{sequence\_number} \ne X_k.\text{sequence\_number} + 1$ | **FAIL (REJECT)** |
| `BUDGET_INFLATION` | $X_{k+1}.\text{budget} > X_k.\text{budget}$ | **FAIL (REJECT)** |
| `PARENT_HASH_MISMATCH` | $X_{k+1}.\text{parent\_state\_hash} \ne \text{SHA-256}(\text{ENC}(X_k))$ | **FAIL (REJECT)** |
