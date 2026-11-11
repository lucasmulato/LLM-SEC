---- MODULE SSI_Kernel_Broken_Inv_TTrace_1794399961 ----
EXTENDS Sequences, TLCExt, SSI_Kernel_Broken_Inv, Toolbox, Naturals, TLC

_expression ==
    LET SSI_Kernel_Broken_Inv_TEExpression == INSTANCE SSI_Kernel_Broken_Inv_TEExpression
    IN SSI_Kernel_Broken_Inv_TEExpression!expression
----

_trace ==
    LET SSI_Kernel_Broken_Inv_TETrace == INSTANCE SSI_Kernel_Broken_Inv_TETrace
    IN SSI_Kernel_Broken_Inv_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        pre_state = ([H |-> [clearance |-> 2, is_active |-> TRUE, expires_at |-> 2, token_valid |-> TRUE, nonce_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_exceeded |-> FALSE, envelope_active |-> TRUE], S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"}], V |-> [is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE]])
        /\
        last_ver_status = ("Valid")
        /\
        epoch = (0)
        /\
        executed = (TRUE)
        /\
        state = ([H |-> [clearance |-> 2, is_active |-> TRUE, expires_at |-> 2, token_valid |-> TRUE, nonce_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_exceeded |-> FALSE, envelope_active |-> TRUE], S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"}], V |-> [is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE], I |-> [budget |-> 1, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> TRUE], P |-> [sequence_number |-> 1, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE]])
        /\
        executed_action = ([id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE])
        /\
        last_action = ([id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE])
        /\
        last_permit = (TRUE)
        /\
        invariant_registry = ({})
    )
----

_init ==
    /\ state = _TETrace[1].state
    /\ executed_action = _TETrace[1].executed_action
    /\ epoch = _TETrace[1].epoch
    /\ last_action = _TETrace[1].last_action
    /\ pre_state = _TETrace[1].pre_state
    /\ last_permit = _TETrace[1].last_permit
    /\ executed = _TETrace[1].executed
    /\ invariant_registry = _TETrace[1].invariant_registry
    /\ last_ver_status = _TETrace[1].last_ver_status
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ state  = _TETrace[i].state
        /\ state' = _TETrace[j].state
        /\ executed_action  = _TETrace[i].executed_action
        /\ executed_action' = _TETrace[j].executed_action
        /\ epoch  = _TETrace[i].epoch
        /\ epoch' = _TETrace[j].epoch
        /\ last_action  = _TETrace[i].last_action
        /\ last_action' = _TETrace[j].last_action
        /\ pre_state  = _TETrace[i].pre_state
        /\ pre_state' = _TETrace[j].pre_state
        /\ last_permit  = _TETrace[i].last_permit
        /\ last_permit' = _TETrace[j].last_permit
        /\ executed  = _TETrace[i].executed
        /\ executed' = _TETrace[j].executed
        /\ invariant_registry  = _TETrace[i].invariant_registry
        /\ invariant_registry' = _TETrace[j].invariant_registry
        /\ last_ver_status  = _TETrace[i].last_ver_status
        /\ last_ver_status' = _TETrace[j].last_ver_status

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("SSI_Kernel_Broken_Inv_TTrace_1794399961.json", _TETrace)

=============================================================================

 Note that you can extract this module `SSI_Kernel_Broken_Inv_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `SSI_Kernel_Broken_Inv_TEExpression.tla` file takes precedence 
  over the module `SSI_Kernel_Broken_Inv_TEExpression` below).

---- MODULE SSI_Kernel_Broken_Inv_TEExpression ----
EXTENDS Sequences, TLCExt, SSI_Kernel_Broken_Inv, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `SSI_Kernel_Broken_Inv` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        state |-> state
        ,executed_action |-> executed_action
        ,epoch |-> epoch
        ,last_action |-> last_action
        ,pre_state |-> pre_state
        ,last_permit |-> last_permit
        ,executed |-> executed
        ,invariant_registry |-> invariant_registry
        ,last_ver_status |-> last_ver_status
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_stateUnchanged |-> state = state'
        
        \* Format the `state` variable as Json value.
        \* ,_stateJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(state)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_stateModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].state # _TETrace[s-1].state
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE SSI_Kernel_Broken_Inv_TETrace ----
\*EXTENDS IOUtils, SSI_Kernel_Broken_Inv, TLC
\*
\*trace == IODeserialize("SSI_Kernel_Broken_Inv_TTrace_1794399961.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE SSI_Kernel_Broken_Inv_TETrace ----
EXTENDS SSI_Kernel_Broken_Inv, TLC

trace == 
    <<
    ([pre_state |-> [H |-> [clearance |-> 2, is_active |-> TRUE, expires_at |-> 2, token_valid |-> TRUE, nonce_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_exceeded |-> FALSE, envelope_active |-> TRUE], S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"}], V |-> [is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE]],last_ver_status |-> "Valid",epoch |-> 0,executed |-> FALSE,state |-> [H |-> [clearance |-> 2, is_active |-> TRUE, expires_at |-> 2, token_valid |-> TRUE, nonce_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_exceeded |-> FALSE, envelope_active |-> TRUE], S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"}], V |-> [is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE]],executed_action |-> "NONE",last_action |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE],last_permit |-> FALSE,invariant_registry |-> {}]),
    ([pre_state |-> [H |-> [clearance |-> 2, is_active |-> TRUE, expires_at |-> 2, token_valid |-> TRUE, nonce_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_exceeded |-> FALSE, envelope_active |-> TRUE], S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"}], V |-> [is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE], I |-> [budget |-> 2, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "a_init", type |-> "READ", risk |-> 0, cost |-> 0, clearance |-> 0, payload_digest_valid |-> TRUE, required_capability |-> "NONE", is_forbidden |-> FALSE, is_executed |-> FALSE], P |-> [sequence_number |-> 0, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE]],last_ver_status |-> "Valid",epoch |-> 0,executed |-> TRUE,state |-> [H |-> [clearance |-> 2, is_active |-> TRUE, expires_at |-> 2, token_valid |-> TRUE, nonce_valid |-> TRUE], CSL |-> [revoked |-> FALSE, envelope_exceeded |-> FALSE, envelope_active |-> TRUE], S |-> [containment_active |-> TRUE, containment_barrier_intact |-> TRUE, quarantine_flag |-> FALSE, risk_bound |-> 2, safety_margin |-> 2, csl_constraints |-> {"q"}], V |-> [is_valid |-> TRUE, certificate_valid |-> TRUE, verifier_identity_valid |-> TRUE], I |-> [budget |-> 1, capabilities |-> {"cap_compute", "cap_read"}, epistemic_confidence_valid |-> TRUE], A |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> TRUE], P |-> [sequence_number |-> 1, parent_hash_valid |-> TRUE, merkle_root_valid |-> TRUE, audit_trail_id_valid |-> TRUE]],executed_action |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE],last_action |-> [id |-> "act_read", type |-> "READ", risk |-> 1, cost |-> 1, clearance |-> 1, payload_digest_valid |-> TRUE, required_capability |-> "cap_read", is_forbidden |-> FALSE, is_executed |-> FALSE],last_permit |-> TRUE,invariant_registry |-> {}])
    >>
----


=============================================================================

---- CONFIG SSI_Kernel_Broken_Inv_TTrace_1794399961 ----
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
\* Generated on Wed Nov 11 09:26:03 BRT 2026