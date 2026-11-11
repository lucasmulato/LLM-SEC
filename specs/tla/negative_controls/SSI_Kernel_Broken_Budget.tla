------------------------ MODULE SSI_Kernel_Broken_Budget ------------------------
(***************************************************************************)
(* NEGATIVE CONTROL 3: Deliberately broken budget monotonicity.            *)
(* State transition erroneously inflates or fails to consume budget.       *)
(* TLC MUST find a counterexample violating BudgetMonotonicity.           *)
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

TypeValid(s) == s.I.epistemic_confidence_valid = TRUE /\ s.A.payload_digest_valid = TRUE
KernelValid(s) == TRUE
CSLValid(s) == s.S.containment_active = TRUE /\ s.S.containment_barrier_intact = TRUE /\ s.S.quarantine_flag = FALSE /\ s.S.csl_constraints /= {}
AuthValid(s) == s.H.is_active = TRUE /\ s.H.token_valid = TRUE /\ s.H.nonce_valid = TRUE /\ s.H.clearance >= s.A.clearance
SafetyValid(s) == s.A.risk <= s.S.risk_bound /\ s.S.safety_margin >= s.S.risk_bound
VerValid(s) == s.V.is_valid = TRUE /\ s.V.verifier_identity_valid = TRUE
ProvValid(s) == (s.P.sequence_number > 0 => s.P.parent_hash_valid = TRUE) /\ s.P.merkle_root_valid = TRUE /\ s.P.audit_trail_id_valid = TRUE

ClauseEvaluates(clause, s) ==
    CASE clause = "TypeValid"   -> TypeValid(s)
      [] clause = "KernelValid" -> KernelValid(s)
      [] clause = "CSLValid"    -> CSLValid(s)
      [] clause = "AuthValid"   -> AuthValid(s)
      [] clause = "SafetyValid" -> SafetyValid(s)
      [] clause = "VerValid"    -> VerValid(s)
      [] clause = "ProvValid"   -> ProvValid(s)
      [] OTHER                  -> FALSE

GlobalInvariant(s, phi) ==
    /\ phi /= {}
    /\ \A clause \in phi : ClauseEvaluates(clause, s)

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
    I |-> [ budget |-> 2, epistemic_confidence_valid |-> TRUE, capabilities |-> Capabilities ],
    S |-> [ containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"} ],
    A |-> DefaultAction,
    H |-> [ token_valid |-> TRUE, nonce_valid |-> TRUE, clearance |-> MaxClearance, is_active |-> TRUE, expires_at |-> MaxEpoch ],
    V |-> [ is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE ],
    P |-> [ sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE ],
    CSL |-> [ revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE ]
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

(* DEFECT INJECTED: Budget is increased instead of consumed *)
EvaluateAndTransition(a, v_status) ==
    LET permit_verdict == PERMIT(state, a, v_status, epoch) IN
    IF permit_verdict
    THEN
        LET candidate_post == [
            state EXCEPT
                !.I.budget = state.I.budget + 1,  \* Defect: budget increases!
                !.A = [a EXCEPT !.is_executed = TRUE],
                !.P.sequence_number = state.P.sequence_number + 1,
                !.P.parent_hash_valid = TRUE
        ] IN
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
        \E v_status \in {"Valid"} :
            EvaluateAndTransition(a, v_status)

Next == ActionStep

Spec == Init /\ [][Next]_vars

BudgetMonotonicity ==
    executed => (state.I.budget <= pre_state.I.budget)

=============================================================================