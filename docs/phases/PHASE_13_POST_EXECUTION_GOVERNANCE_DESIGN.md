# Phase 13 Design: Post-Execution Governance and Auditability

Status: DESIGN ONLY - No Implementation
Version: Draft 1.0
Date: 2026-02-05

## Document Purpose

This document describes the design goals, concepts, and boundaries for Phase 13
of AICtrl. Phase 13 focuses on governance, traceability, and operational control
for the execution capabilities introduced in Phase 12.

CRITICAL: This document is for design review only. Implementation belongs to
Phase 14 or later, pending approval of this design.

--------------------------------------------------------------------------------

## 1. Governance Goals

### 1.1 Risks Phase 13 Intends to Mitigate

Phase 12 introduced controlled execution with approval gates. While this provides
basic safety, several governance risks remain unaddressed:

R1. APPROVAL REPLAY
    An approval artifact created for one execution could potentially be reused
    for subsequent executions of the same proposal, bypassing the intent of
    single-use authorization.

R2. STALE APPROVALS
    An approval created at time T might be executed at time T+N where the
    operational context has changed significantly (different environment,
    different operator on duty, changed risk posture).

R3. INCOMPLETE AUDIT TRAIL
    Execution results are returned but not persisted. If an execution occurs
    and the operator loses the output, there is no recovery path and no
    independent verification possible.

R4. MISSING EXECUTION CONTEXT
    Executions occur without capturing environmental context (hostname, user,
    working directory, environment variables) that would be essential for
    forensic analysis.

R5. OPERATOR ACCOUNTABILITY GAP
    The approved_by field captures who approved, but there is no binding
    between the approver and the actual executor. These may be different
    parties with different authorization levels.

R6. RESULT TAMPERING
    Execution results are returned to the caller but are not cryptographically
    bound to the proposal, approval, or execution context. Results could be
    modified after the fact.

### 1.2 Explicit Non-Goals (What Phase 13 Will NOT Do)

NG1. Phase 13 will NOT expand execution capabilities.
     No new adapters, no new actions, no relaxation of the dangerous gate.

NG2. Phase 13 will NOT introduce network operations.
     All governance mechanisms must work offline and locally.

NG3. Phase 13 will NOT implement automated policy enforcement.
     Policies remain advisory; humans remain in the decision loop.

NG4. Phase 13 will NOT create a trust store or PKI infrastructure.
     Cryptographic operations use explicit keys, not implicit trust.

NG5. Phase 13 will NOT implement revocation mechanisms.
     Approvals cannot be revoked after creation; instead, they expire.

NG6. Phase 13 will NOT add interactive prompts or user interfaces.
     All operations remain non-interactive and scriptable.

NG7. Phase 13 will NOT modify the approval or execution flow from Phase 12.
     Existing commands (propose, review, approve, run) retain their semantics.

--------------------------------------------------------------------------------

## 2. Audit and Evidence Model

### 2.1 Artifact Lifecycle

The governance model introduces a complete artifact chain:

    PROPOSAL (Phase 12)
        |
        v
    REVIEW (Phase 12, implicit in approve/run)
        |
        v
    APPROVAL (Phase 12)
        |
        v
    EXECUTION RECEIPT (Phase 13 - NEW)
        |
        v
    RESULT ATTESTATION (Phase 13 - NEW)

### 2.2 Execution Receipt Concept

An Execution Receipt is an artifact created BEFORE adapter execution begins.
It captures the intent and context of the execution attempt.

Conceptual fields:
- receipt_id: Unique identifier for this execution attempt
- proposal_id: Reference to the proposal being executed
- approval_id: Reference to the approval authorizing execution
- content_hash: Hash of proposal at execution time (re-verified)
- executed_by: Identity of the operator invoking exec run
- execution_context: Environmental snapshot (see 2.4)
- initiated_at: Timestamp when execution was initiated
- receipt_hash: Hash of this receipt for integrity verification

The receipt is created BEFORE execution, ensuring that even failed executions
leave an audit trail.

### 2.3 Result Attestation Concept

A Result Attestation is an artifact created AFTER adapter execution completes.
It captures the outcome and binds it cryptographically to the execution chain.

Conceptual fields:
- attestation_id: Unique identifier for this result
- receipt_id: Reference to the execution receipt
- proposal_id: Reference back to the original proposal
- completed_at: Timestamp when execution completed
- success: Boolean indicating execution success
- exit_code: Adapter exit code
- result_hash: Hash of the adapter result payload
- result_summary: Truncated or redacted result for audit logs
- attestation_signature: Optional cryptographic signature (if key provided)

### 2.4 Execution Context Capture

The execution context provides environmental forensics. Captured fields:

- hostname: Machine where execution occurred
- username: OS user identity
- working_directory: Current working directory
- aictrl_version: Version of AICtrl performing execution
- aictrl_phase: Phase number at execution time
- environment_hash: Hash of selected environment variables (not values)
- timestamp_utc: Execution start time in UTC
- boot_id: If available, system boot identifier for session correlation

Note: Sensitive values (passwords, tokens) must NEVER be captured.
Only variable names are hashed, not their values.

### 2.5 Evidence Chain Integrity

All artifacts in the chain reference their predecessors by ID and hash:

    Proposal
      content_hash <------ Approval.content_hash
                              |
    Approval                  |
      approval_id <----+      |
      proposal_id <----|------+
                       |
    Receipt            |
      receipt_id <-----+------ Attestation.receipt_id
      approval_id <----+
      proposal_id
      content_hash (re-verified)

Breaking any link in this chain should be detectable through hash verification.

--------------------------------------------------------------------------------

## 3. Policy and Control Concepts

### 3.1 Time-Based Approval Validity

Concept: Approvals should have a validity window.

An approval created at time T should only be valid for execution within a
defined window (e.g., T to T+1hour). After the window expires, the approval
is considered stale and execution should be denied.

Design considerations:
- The validity window should be configurable (environment variable or flag)
- Default validity should be conservative (e.g., 1 hour)
- Expired approvals return a deterministic exit code (2)
- Expiration is checked at run time, not at approval time
- Clock skew tolerance should be minimal (seconds, not minutes)

This mitigates risk R2 (stale approvals) without requiring revocation.

### 3.2 Replay Prevention

Concept: Each approval should be usable exactly once.

After an approval is used for execution (successfully or not), it should be
marked as consumed. Subsequent attempts to use the same approval should fail.

Design considerations:
- Consumption is recorded in the Result Attestation
- The attestation includes the approval_id
- Before execution, check if an attestation already exists for this approval
- Replay detection is local (file-based), not networked
- Missing attestation files mean replay cannot be detected (fail-open vs fail-closed decision required)

This mitigates risk R1 (approval replay).

### 3.3 Operator Accountability

Concept: The executor identity should be captured and may differ from approver.

The approval.approved_by field captures who authorized the operation.
The receipt.executed_by field captures who actually ran it.

Design considerations:
- executed_by is captured from environment (USER, LOGNAME)
- executed_by may be overridden with an explicit flag for audit purposes
- Mismatch between approver and executor is logged but not blocked
- Organizations may layer additional policy on top (e.g., approver != executor requirement)

This mitigates risk R5 (operator accountability gap).

### 3.4 Environment and Context Binding

Concept: Approvals may be bound to specific execution contexts.

An approval created on machine A might not be valid for execution on machine B.
Context binding allows operators to restrict where approvals can be used.

Design considerations:
- Context binding is OPTIONAL (not enforced by default)
- When enabled, approval captures expected_context
- At run time, actual context is compared to expected_context
- Mismatch results in denial (exit code 2)
- Binding fields might include: hostname, username, working_directory

This provides defense against approval exfiltration (approval file copied
to unauthorized machine).

--------------------------------------------------------------------------------

## 4. Failure and Abuse Scenarios

### 4.1 Approval Reuse (Replay Attack)

Scenario: Operator creates one approval, uses it for multiple executions.

Without Phase 13:
- Multiple executions succeed
- No audit trail of repeated use
- Intent of single-use authorization bypassed

With Phase 13 (replay prevention):
- First execution creates attestation referencing approval_id
- Second execution checks for existing attestation
- Second execution denied with "approval already consumed" error
- Exit code: 2 (deterministic denial)

### 4.2 Stale Approval Use

Scenario: Approval created Monday, used Friday when context has changed.

Without Phase 13:
- Execution proceeds regardless of age
- Operational context may have changed significantly
- Approval reflects outdated risk assessment

With Phase 13 (time-based validity):
- Approval has validity_window (e.g., 1 hour)
- Friday execution checks approval.approved_at against current time
- Execution denied with "approval expired" error
- Exit code: 2 (deterministic denial)

### 4.3 Missing Artifacts

Scenario: Operator deletes attestation files to hide activity.

Without Phase 13:
- No attestation files exist
- No evidence of prior executions
- Replay prevention cannot function

With Phase 13:
- Receipt is created BEFORE execution (harder to delete preemptively)
- Attestation absence can be detected by comparing receipts to attestations
- Gap between receipt and attestation indicates abnormal termination or tampering
- Policy decision: fail-open (allow replay) vs fail-closed (deny if uncertain)

Recommendation: Provide both modes, default to fail-closed for dangerous adapters.

### 4.4 Result Tampering

Scenario: Operator modifies execution result after the fact.

Without Phase 13:
- Results are ephemeral (returned, not persisted)
- No integrity verification possible
- Falsified results cannot be detected

With Phase 13:
- Attestation includes result_hash
- Original result can be verified against stored hash
- Signed attestation (if key provided) prevents attestation modification
- Tampering is detectable, not preventable (evidence-based model)

### 4.5 Context Exfiltration

Scenario: Approval file copied from authorized machine to unauthorized machine.

Without Phase 13:
- Approval is valid on any machine
- No binding to original context
- Lateral movement of approval possible

With Phase 13 (context binding enabled):
- Approval captures expected hostname/user at creation time
- Run on different machine fails context check
- Exit code: 2 (deterministic denial)
- Error message indicates context mismatch

### 4.6 Clock Manipulation

Scenario: Operator sets system clock backward to extend approval validity.

Phase 13 consideration:
- Time-based validity relies on system clock
- Clock manipulation is outside AICtrl's control
- Mitigation: capture and compare boot_id to detect reboot-based clock reset
- Mitigation: log clock anomalies (large jumps) in receipts
- Full mitigation requires secure time source (out of scope)

--------------------------------------------------------------------------------

## 5. Phase Boundaries

### 5.1 Phase 13 Completion Criteria

Phase 13 design is complete when:

C1. This design document has been reviewed and approved.

C2. Governance model has been validated against threat scenarios.

C3. Artifact schemas have been fully specified (separate schema document).

C4. Policy configurations have been enumerated with defaults.

C5. Failure modes have been documented with deterministic exit codes.

C6. Test scenarios have been outlined (not implemented).

Phase 13 design is NOT complete until all stakeholders agree that the
governance model is sufficient for the operational risks being mitigated.

### 5.2 Implementation Boundary

EXPLICIT STATEMENT:

All implementation of Phase 13 concepts belongs to Phase 14 or later.

Phase 13 is a DESIGN-ONLY phase. The deliverables are:
- This design document
- Schema specifications (future document)
- Policy configuration reference (future document)
- Test scenario outlines (future document)

No code changes, no CLI modifications, no version bumps, and no baseline
test additions should occur as part of Phase 13.

### 5.3 Phase 14 Preview

Phase 14 (future) would implement the concepts designed in Phase 13:
- Execution Receipt creation
- Result Attestation creation
- Time-based validity enforcement
- Replay prevention mechanism
- Context binding (optional)
- New baseline tests for governance behaviors

Phase 14 should not introduce any concepts not described in this document.

--------------------------------------------------------------------------------

## 6. Open Questions for Review

Q1. Should replay prevention be fail-open or fail-closed by default?
    - Fail-open: Allow execution if attestation state is uncertain
    - Fail-closed: Deny execution if prior attestation might exist

Q2. What should the default approval validity window be?
    - Candidates: 15 minutes, 1 hour, 4 hours, 24 hours
    - Consideration: Too short is operationally burdensome, too long defeats purpose

Q3. Should context binding be opt-in or opt-out?
    - Opt-in: Disabled by default, enabled with flag
    - Opt-out: Enabled by default, disabled with flag

Q4. Should result_hash include full output or truncated output?
    - Full: Complete forensic capability but potentially large
    - Truncated: Smaller attestations but lossy

Q5. Should signed attestations be mandatory for dangerous adapters?
    - Mandatory: Forces key management, strong auditability
    - Optional: Flexible, but allows unsigned attestations

--------------------------------------------------------------------------------

## 7. Document History

Draft 1.0 (2026-02-05):
- Initial design document
- Covers governance goals, audit model, policy concepts, failure scenarios
- Defines phase boundaries
- Lists open questions for review

--------------------------------------------------------------------------------

END OF DOCUMENT
