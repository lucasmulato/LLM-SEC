---- MODULE SSI_Kernel_Broken_Auth_TTrace_1794399932 ----
EXTENDS Sequences, TLCExt, Toolbox, SSI_Kernel_Broken_Auth, Naturals, TLC

_expression ==
    LET SSI_Kernel_Broken_Auth_TEExpression == INSTANCE SSI_Kernel_Broken_Auth_TEExpression
    IN SSI_Kernel_Broken_Auth_TEExpression!expression
----

_trace ==
    LET SSI_Kernel_Broken_Auth_TETrace == INSTANCE SSI_Kernel_Broken_Auth_TETrace
    IN SSI_Kernel_Broken_Auth_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        pre_state = ([S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]])
        /\
        last_ver_status = ("Valid")
        /\
        epoch = (2)
        /\
        executed = (TRUE)
        /\
        last_action = ([id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE])
        /\
        state = ([S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 1, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> TRUE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 1, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]])
        /\
        executed_action = ([id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE])
        /\
        last_permit = (TRUE)
        /\
        invariant_registry = ({"TypeValid", "KernelValid", "CSLValid", "AuthValid", "SafetyValid", "VerValid", "ProvValid"})
    )
----

_init ==
    /\ epoch = _TETrace[1].epoch
    /\ last_action = _TETrace[1].last_action
    /\ executed = _TETrace[1].executed
    /\ state = _TETrace[1].state
    /\ pre_state = _TETrace[1].pre_state
    /\ executed_action = _TETrace[1].executed_action
    /\ last_ver_status = _TETrace[1].last_ver_status
    /\ invariant_registry = _TETrace[1].invariant_registry
    /\ last_permit = _TETrace[1].last_permit
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ epoch  = _TETrace[i].epoch
        /\ epoch' = _TETrace[j].epoch
        /\ last_action  = _TETrace[i].last_action
        /\ last_action' = _TETrace[j].last_action
        /\ executed  = _TETrace[i].executed
        /\ executed' = _TETrace[j].executed
        /\ state  = _TETrace[i].state
        /\ state' = _TETrace[j].state
        /\ pre_state  = _TETrace[i].pre_state
        /\ pre_state' = _TETrace[j].pre_state
        /\ executed_action  = _TETrace[i].executed_action
        /\ executed_action' = _TETrace[j].executed_action
        /\ last_ver_status  = _TETrace[i].last_ver_status
        /\ last_ver_status' = _TETrace[j].last_ver_status
        /\ invariant_registry  = _TETrace[i].invariant_registry
        /\ invariant_registry' = _TETrace[j].invariant_registry
        /\ last_permit  = _TETrace[i].last_permit
        /\ last_permit' = _TETrace[j].last_permit

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("SSI_Kernel_Broken_Auth_TTrace_1794399932.json", _TETrace)

=============================================================================

 Note that you can extract this module `SSI_Kernel_Broken_Auth_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `SSI_Kernel_Broken_Auth_TEExpression.tla` file takes precedence 
  over the module `SSI_Kernel_Broken_Auth_TEExpression` below).

---- MODULE SSI_Kernel_Broken_Auth_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, SSI_Kernel_Broken_Auth, Naturals, TLC

expression == 
    [
        \* To hide variables of the `SSI_Kernel_Broken_Auth` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        epoch |-> epoch
        ,last_action |-> last_action
        ,executed |-> executed
        ,state |-> state
        ,pre_state |-> pre_state
        ,executed_action |-> executed_action
        ,last_ver_status |-> last_ver_status
        ,invariant_registry |-> invariant_registry
        ,last_permit |-> last_permit
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_epochUnchanged |-> epoch = epoch'
        
        \* Format the `epoch` variable as Json value.
        \* ,_epochJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(epoch)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_epochModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].epoch # _TETrace[s-1].epoch
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE SSI_Kernel_Broken_Auth_TETrace ----
\*EXTENDS IOUtils, SSI_Kernel_Broken_Auth, TLC
\*
\*trace == IODeserialize("SSI_Kernel_Broken_Auth_TTrace_1794399932.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE SSI_Kernel_Broken_Auth_TETrace ----
EXTENDS SSI_Kernel_Broken_Auth, TLC

trace == 
    <<
    ([pre_state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],last_ver_status |-> "Valid",epoch |-> 0,executed |-> FALSE,last_action |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE],state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],executed_action |-> "NONE",last_permit |-> FALSE,invariant_registry |-> {"TypeValid", "KernelValid", "CSLValid", "AuthValid", "SafetyValid", "VerValid", "ProvValid"}]),
    ([pre_state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],last_ver_status |-> "Valid",epoch |-> 1,executed |-> FALSE,last_action |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE],state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],executed_action |-> "NONE",last_permit |-> FALSE,invariant_registry |-> {"TypeValid", "KernelValid", "CSLValid", "AuthValid", "SafetyValid", "VerValid", "ProvValid"}]),
    ([pre_state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],last_ver_status |-> "Valid",epoch |-> 2,executed |-> FALSE,last_action |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE],state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],executed_action |-> "NONE",last_permit |-> FALSE,invariant_registry |-> {"TypeValid", "KernelValid", "CSLValid", "AuthValid", "SafetyValid", "VerValid", "ProvValid"}]),
    ([pre_state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],last_ver_status |-> "Valid",epoch |-> 2,executed |-> TRUE,last_action |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE],state |-> [S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, csl_constraints |-> {"q"}, safety_margin |-> 2], V |-> [is_valid |-> TRUE, verifier_identity_valid |-> TRUE, certificate_valid |-> TRUE], I |-> [budget |-> 1, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> TRUE], H |-> [clearance |-> 2, is_active |-> TRUE, token_valid |-> TRUE, nonce_valid |-> TRUE, expires_at |-> 1], P |-> [sequence_number |-> 1, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_active |-> TRUE, envelope_exceeded |-> FALSE]],executed_action |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE],last_permit |-> TRUE,invariant_registry |-> {"TypeValid", "KernelValid", "CSLValid", "AuthValid", "SafetyValid", "VerValid", "ProvValid"}])
    >>
----


=============================================================================

---- CONFIG SSI_Kernel_Broken_Auth_TTrace_1794399932 ----
CONSTANTS
    MaxBudget = 2
    MaxEpoch = 2
    MaxClearance = 2
    MaxSequence = 2

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Wed Nov 11 09:25:34 BRT 2026