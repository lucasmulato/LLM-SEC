----------------------------- MODULE SSI_Kernel -----------------------------
(***************************************************************************)
(* Normative Formal Specification of the SSI Kernel & Execution Gate.     *)
(* Traceable to Proof Obligations PO-3, PO-4, PO-5, and PO-9.             *)
(* Follows SSI Axiomatic System v1.0 and docs/REQUIREMENTS.md.             *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxBudget,
    MaxEpoch,
    MaxClearance,
    MaxSequence

Capabilities == {"cap_compute", "cap_read"}

InvariantClauses == {"TypeValid", "KernelValid", "CSLValid", "AuthValid", "SafetyValid", "VerValid", "ProvValid"}

Actions == {
    [
        id |-> "act_read",
        type |-> "READ",
        risk |-> 1,
        cost |-> 1,
        clearance |-> 1,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_read",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_compute",
        type |-> "COMPUTE",
        risk |-> 1,
        cost |-> 2,
        clearance |-> 2,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_compute",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_overbudget",
        type |-> "READ",
        risk |-> 1,
        cost |-> 4,
        clearance |-> 1,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_read",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_high_risk",
        type |-> "MUTATE_ENVIRONMENT",
        risk |-> 3,
        cost |-> 1,
        clearance |-> 1,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_read",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_high_clearance",
        type |-> "READ",
        risk |-> 1,
        cost |-> 1,
        clearance |-> 3,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_read",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_halt",
        type |-> "SYSTEM_HALT",
        risk |-> 0,
        cost |-> 0,
        clearance |-> 0,
        payload_digest_valid |-> TRUE,
        required_capability |-> "NONE",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_forbidden",
        type |-> "READ",
        risk |-> 1,
        cost |-> 1,
        clearance |-> 1,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_read",
        is_forbidden |-> TRUE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_invalid_payload",
        type |-> "READ",
        risk |-> 1,
        cost |-> 1,
        clearance |-> 1,
        payload_digest_valid |-> FALSE,
        required_capability |-> "cap_read",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ],
    [
        id |-> "act_missing_cap",
        type |-> "COMMUNICATE",
        risk |-> 1,
        cost |-> 1,
        clearance |-> 1,
        payload_digest_valid |-> TRUE,
        required_capability |-> "cap_network",
        is_forbidden |-> FALSE,
        is_executed |-> FALSE
    ]
}

VARIABLES
    state,
    pre_state,
    epoch,
    last_action,
    last_ver_status,
    last_permit,
    executed,
    executed_action,
    invariant_registry

vars == << state, pre_state, epoch, last_action, last_ver_status,
           last_permit, executed, executed_action, invariant_registry >>

(***************************************************************************)
(* Sub-Predicates of PERMIT(X, a)                                          *)
(***************************************************************************)

AuthCheck(s, a, ep) ==
    /\ s.H.is_active = TRUE
    /\ ep <= s.H.expires_at
    /\ s.H.clearance >= a.clearance
    /\ s.H.token_valid = TRUE
    /\ s.H.nonce_valid = TRUE
    /\ s.CSL.revoked = FALSE
    /\ s.CSL.envelope_exceeded = FALSE

SafeActionCheck(s, a) ==
    /\ s.S.containment_active = TRUE
    /\ s.S.containment_barrier_intact = TRUE
    /\ s.S.quarantine_flag = FALSE
    /\ a.type /= "SYSTEM_HALT"
    /\ a.risk <= s.S.risk_bound
    /\ a.is_forbidden = FALSE

VerCheck(s, a, v_status) ==
    /\ v_status = "Valid"
    /\ s.V.is_valid = TRUE
    /\ a.payload_digest_valid = TRUE

CapCheck(s, a) ==
    /\ s.I.budget >= a.cost
    /\ (a.required_capability = "NONE" \/ a.required_capability \in s.I.capabilities)

PERMIT(s, a, v_status, ep) ==
    /\ AuthCheck(s, a, ep)
    /\ SafeActionCheck(s, a)
    /\ VerCheck(s, a, v_status)
    /\ CapCheck(s, a)

(***************************************************************************)
(* Invariant Registry & Global Invariant I(X)                              *)
(***************************************************************************)

TypeValid(s) ==
    /\ s.I.epistemic_confidence_valid = TRUE
    /\ s.A.payload_digest_valid = TRUE

KernelValid(s) ==
    TRUE

CSLValid(s) ==
    /\ s.S.containment_active = TRUE
    /\ s.S.containment_barrier_intact = TRUE
    /\ s.S.quarantine_flag = FALSE
    /\ s.S.csl_constraints /= {}

AuthValid(s) ==
    /\ s.H.is_active = TRUE
    /\ s.H.token_valid = TRUE
    /\ s.H.nonce_valid = TRUE
    /\ s.H.clearance >= s.A.clearance

SafetyValid(s) ==
    /\ s.A.risk <= s.S.risk_bound
    /\ s.S.safety_margin >= s.S.risk_bound

VerValid(s) ==
    /\ s.V.is_valid = TRUE
    /\ s.V.verifier_identity_valid = TRUE

ProvValid(s) ==
    /\ (s.P.sequence_number > 0 => s.P.parent_hash_valid = TRUE)
    /\ s.P.merkle_root_valid = TRUE
    /\ s.P.audit_trail_id_valid = TRUE

ClauseEvaluates(clause, s) ==
    CASE clause = "TypeValid"   -> TypeValid(s)
      [] clause = "KernelValid" -> KernelValid(s)
      [] clause = "CSLValid"    -> CSLValid(s)
      [] clause = "AuthValid"   -> AuthValid(s)
      [] clause = "SafetyValid" -> SafetyValid(s)
      [] clause = "VerValid"    -> VerValid(s)
      [] clause = "ProvValid"   -> ProvValid(s)
      [] OTHER                  -> FALSE

(* Fail-Closed: empty invariant registry Phi = {} is NEVER safe *)
GlobalInvariant(s, phi) ==
    /\ phi /= {}
    /\ \A clause \in phi : ClauseEvaluates(clause, s)

(***************************************************************************)
(* Initial State                                                           *)
(***************************************************************************)

DefaultAction == [
    id |-> "a_init",
    type |-> "READ",
    risk |-> 0,
    cost |-> 0,
    clearance |-> 0,
    payload_digest_valid |-> TRUE,
    required_capability |-> "NONE",
    is_forbidden |-> FALSE,
    is_executed |-> FALSE
]

InitialState == [
    I |-> [
        budget |-> MaxBudget,
        epistemic_confidence_valid |-> TRUE,
        capabilities |-> Capabilities
    ],
    S |-> [
        containment_active |-> TRUE,
        containment_barrier_intact |-> TRUE,
        quarantine_flag |-> FALSE,
        risk_bound |-> 2,
        safety_margin |-> 2,
        csl_constraints |-> {"constraint_bounded_cost"}
    ],
    A |-> DefaultAction,
    H |-> [
        token_valid |-> TRUE,
        nonce_valid |-> TRUE,
        clearance |-> MaxClearance,
        is_active |-> TRUE,
        expires_at |-> MaxEpoch
    ],
    V |-> [
        is_valid |-> TRUE,
        certificate_valid |-> TRUE,
        verifier_identity_valid |-> TRUE
    ],
    P |-> [
        sequence_number |-> 0,
        parent_hash_valid |-> TRUE,
        merkle_root_valid |-> TRUE,
        audit_trail_id_valid |-> TRUE
    ],
    CSL |-> [
        revoked |-> FALSE,
        envelope_active |-> TRUE,
        envelope_exceeded |-> FALSE
    ]
]

Init ==
    /\ state = InitialState
    /\ pre_state = InitialState
    /\ epoch = 0
    /\ last_action = DefaultAction
    /\ last_ver_status = "Valid"
    /\ last_permit = FALSE
    /\ executed = FALSE
    /\ executed_action = "NONE"
    /\ invariant_registry = InvariantClauses

(***************************************************************************)
(* State Transition Relations                                              *)
(***************************************************************************)

TickEpoch ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ UNCHANGED << state, pre_state, last_action, last_ver_status,
                    last_permit, executed, executed_action, invariant_registry >>

RevokeCSL ==
    /\ state.CSL.revoked = FALSE
    /\ state' = [state EXCEPT !.CSL.revoked = TRUE]
    /\ pre_state' = state
    /\ executed' = FALSE
    /\ executed_action' = "NONE"
    /\ last_permit' = FALSE
    /\ UNCHANGED << epoch, last_action, last_ver_status, invariant_registry >>

ExceedEnvelope ==
    /\ state.CSL.envelope_exceeded = FALSE
    /\ state' = [state EXCEPT !.CSL.envelope_exceeded = TRUE]
    /\ pre_state' = state
    /\ executed' = FALSE
    /\ executed_action' = "NONE"
    /\ last_permit' = FALSE
    /\ UNCHANGED << epoch, last_action, last_ver_status, invariant_registry >>

(* Evaluate candidate action through 4-stage pipeline *)
EvaluateAndTransition(a, v_status) ==
    LET permit_verdict == PERMIT(state, a, v_status, epoch) IN
    IF permit_verdict
    THEN
        (* Candidate post-state transition *)
        LET candidate_post == [
            state EXCEPT
                !.I.budget = state.I.budget - a.cost,
                !.A = [a EXCEPT !.is_executed = TRUE],
                !.P.sequence_number = state.P.sequence_number + 1,
                !.P.parent_hash_valid = TRUE
        ] IN
        (* INVARIANT_CHECK stage: evaluate registry Phi over candidate post-state *)
        IF GlobalInvariant(candidate_post, invariant_registry) /\ candidate_post.P.sequence_number <= MaxSequence
        THEN
            (* COMMIT stage: commit state and release execution *)
            /\ state' = candidate_post
            /\ pre_state' = state
            /\ epoch' = epoch
            /\ last_action' = a
            /\ last_ver_status' = v_status
            /\ last_permit' = TRUE
            /\ executed' = TRUE
            /\ executed_action' = a
            /\ UNCHANGED invariant_registry
        ELSE
            (* Invariant check failed: REJECT with zero state change and zero effect *)
            /\ state' = state
            /\ pre_state' = state
            /\ epoch' = epoch
            /\ last_action' = a
            /\ last_ver_status' = v_status
            /\ last_permit' = FALSE
            /\ executed' = FALSE
            /\ executed_action' = "NONE"
            /\ UNCHANGED invariant_registry
    ELSE
        (* PERMIT denied: REJECT with zero state change and zero effect *)
        /\ state' = state
        /\ pre_state' = state
        /\ epoch' = epoch
        /\ last_action' = a
        /\ last_ver_status' = v_status
        /\ last_permit' = FALSE
        /\ executed' = FALSE
        /\ executed_action' = "NONE"
        /\ UNCHANGED invariant_registry

ActionStep ==
    \E a \in Actions :
        \E v_status \in {"Valid", "Invalid", "Unknown"} :
            EvaluateAndTransition(a, v_status)

Next ==
    \/ TickEpoch
    \/ RevokeCSL
    \/ ExceedEnvelope
    \/ ActionStep

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* TLC Mechanically Checked Invariants & Theorems                          *)
(***************************************************************************)

(* T1: Permit Soundness (PO-3, PO-4) : ~PERMIT => ~EXECUTE *)
T1_PermitSoundness ==
    executed =>
        /\ last_permit = TRUE
        /\ AuthCheck(pre_state, executed_action, epoch)
        /\ SafeActionCheck(pre_state, executed_action)
        /\ VerCheck(pre_state, executed_action, last_ver_status)
        /\ CapCheck(pre_state, executed_action)

(* T3: Invariant Preservation (PO-5) : Post-state satisfies global invariant *)
T3_InvariantPreservation ==
    executed => GlobalInvariant(state, invariant_registry)

(* T5: Reachable State Safety : All reachable states are invariant-compliant *)
T5_ReachableStateSafety ==
    GlobalInvariant(state, invariant_registry)

(* C1: Authorization Continuity : Expired/revoked/exceeded CSL strictly denies permit *)
C1_AuthorizationContinuity ==
    (pre_state.CSL.revoked = TRUE
     \/ pre_state.CSL.envelope_exceeded = TRUE
     \/ epoch > pre_state.H.expires_at
     \/ pre_state.H.is_active = FALSE) => (last_permit = FALSE)

(* Monotonic Cognitive Budget Consumption *)
BudgetMonotonicity ==
    executed => (state.I.budget <= pre_state.I.budget)

(* Monotonic Sequence Progression *)
SequenceMonotonicity ==
    executed => (state.P.sequence_number = pre_state.P.sequence_number + 1)

(* Tri-State Fail-Closed: Unknown verification status strictly blocks permit *)
FailClosedUnknownVerification ==
    (last_ver_status = "Unknown") => (last_permit = FALSE)

(* Zero Execution on Rejection *)
ZeroExecutionOnReject ==
    (~last_permit) => (~executed)

=============================================================================