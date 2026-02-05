# Phase 14 Part 1 Design: Post-Execution Observability Layer

Status: DESIGN ONLY - No Implementation
Version: Draft 1.0
Date: 2026-02-04

## Document Purpose

This document describes the design for Phase 14 Part 1 of AICtrl. This phase
introduces a post-execution observability layer that records execution evidence
without altering execution behavior or outcomes.

CRITICAL: This document is for design review only. Implementation requires
approval of this design and alignment with Phase 13 governance model.

--------------------------------------------------------------------------------

## 1. Purpose and Scope

### 1.1 What Phase 14 Part 1 Does

Phase 14 Part 1 introduces observability artifacts for execution operations.
These artifacts provide evidence of what occurred during execution without
influencing whether or how execution proceeds.

The observability layer:
- Records execution intent before adapter invocation (Execution Receipt)
- Records execution outcome after adapter completion (Result Attestation)
- Links these artifacts to the existing proposal/approval chain
- Surfaces warnings when artifact creation fails

### 1.2 What Phase 14 Part 1 Does NOT Do

EXPLICIT STATEMENT: This phase is OBSERVABILITY ONLY.

Phase 14 Part 1 does NOT:
- Block execution for any reason related to observability
- Prevent execution based on prior attestation state
- Enforce approval expiration or time-based validity
- Enforce single-use approval constraints (replay prevention)
- Verify operator identity beyond recording it
- Bind approvals to specific execution contexts
- Report evidence to any network endpoint
- Modify the execution flow established in Phase 12

### 1.3 Failure Tolerance Principle

EXPLICIT STATEMENT: Failures in observability do NOT block execution.

If the observability layer fails to create a receipt or attestation:
- Execution proceeds normally
- A warning is included in the execution result
- The missing artifact is noted for audit purposes
- No error code is returned for observability failures alone

Rationale: Observability is a secondary concern. The primary function of
exec run is to execute the approved proposal. Blocking execution because
evidence could not be recorded would invert the priority relationship.

--------------------------------------------------------------------------------

## 2. Artifact Model

### 2.1 Execution Receipt

An Execution Receipt is an artifact created BEFORE adapter execution begins.
It captures the intent and context of the execution attempt.

Purpose: Provide evidence that an execution was attempted, even if the
adapter fails, hangs, or is terminated externally.

Required fields:
- receipt_id: Unique identifier for this execution attempt
- receipt_version: Schema version for this receipt format
- created_at: Timestamp when receipt was created (UTC ISO 8601)
- proposal_id: Reference to the proposal being executed
- approval_id: Reference to the approval authorizing execution
- content_hash: Hash of proposal content at execution time
- content_hash_algorithm: Algorithm used (sha256)
- executed_by: Identity of operator invoking exec run
- execution_context: Environmental snapshot (see 2.3)
- receipt_hash: Hash of this receipt for integrity verification
- receipt_hash_algorithm: Algorithm used (sha256)

Hashing strategy:
- receipt_hash is computed over all other fields in canonical order
- Canonical order: alphabetical by field name
- JSON serialization: compact, sorted keys, no trailing whitespace
- Hash algorithm: SHA-256 (consistent with Phase 12)

Relationship to Phase 12 artifacts:
- References proposal_id from the proposal artifact
- References approval_id from the approval artifact
- Recomputes and stores content_hash for verification

Relationship to Phase 13 lifecycle:
- Implements the Execution Receipt concept from Phase 13 Section 2.2
- Created at the position defined in Phase 13 Section 2.1 artifact chain

### 2.2 Result Attestation

A Result Attestation is an artifact created AFTER adapter execution completes.
It captures the outcome and binds it to the execution chain.

Purpose: Provide evidence of what the adapter returned, enabling later
verification that results have not been modified.

Required fields:
- attestation_id: Unique identifier for this result
- attestation_version: Schema version for this attestation format
- created_at: Timestamp when attestation was created (UTC ISO 8601)
- receipt_id: Reference to the execution receipt
- proposal_id: Reference to the original proposal
- approval_id: Reference to the approval
- completed_at: Timestamp when adapter execution completed (UTC ISO 8601)
- duration_ms: Execution duration in milliseconds
- success: Boolean indicating adapter-reported success
- exit_code: Adapter exit code (integer)
- result_hash: Hash of the complete adapter result payload
- result_hash_algorithm: Algorithm used (sha256)
- result_summary: Truncated result for audit logs (first 256 characters)
- warnings: List of warnings encountered during execution
- attestation_hash: Hash of this attestation for integrity verification
- attestation_hash_algorithm: Algorithm used (sha256)

Hashing strategy:
- result_hash is computed over the complete adapter result JSON
- attestation_hash is computed over all other attestation fields
- Same canonical serialization as Execution Receipt
- Hash algorithm: SHA-256 (consistent with Phase 12)

Relationship to Phase 12 artifacts:
- References proposal_id and approval_id for traceability
- Contains hash of actual execution result

Relationship to Phase 13 lifecycle:
- Implements the Result Attestation concept from Phase 13 Section 2.3
- Created at the final position in Phase 13 Section 2.1 artifact chain

### 2.3 Execution Context

The execution context captures environmental information for forensic purposes.
This context is embedded in the Execution Receipt.

Required fields:
- hostname: Machine hostname where execution occurred
- username: OS username from environment (USER or LOGNAME)
- working_directory: Current working directory at execution time
- aictrl_version: Version string of AICtrl performing execution
- aictrl_phase: Phase number at execution time (integer)
- timestamp_utc: Execution start time (UTC ISO 8601)
- environment_variables: List of environment variable names present (not values)

SECURITY CONSTRAINT: Values of environment variables are NEVER captured.
Only variable names are recorded. This prevents accidental capture of
secrets, tokens, or credentials in observability artifacts.

Optional fields (captured if available):
- boot_id: System boot identifier for session correlation
- process_id: PID of the aictrl process

--------------------------------------------------------------------------------

## 3. Evidence Chain

### 3.1 Artifact Linkage

The complete evidence chain links all artifacts by ID and hash:

    Proposal (Phase 12)
      proposal_id  <-----------------+
      content_hash <--------------+  |
                                  |  |
    Approval (Phase 12)           |  |
      approval_id  <-----------+  |  |
      proposal_id  ------------|--|--+
      content_hash ------------|--+
                               |
    Execution Receipt (Phase 14 Part 1)
      receipt_id   <-----------|---------+
      approval_id  ------------+         |
      proposal_id  ----------------------+
      content_hash (re-verified)         |
                                         |
    Result Attestation (Phase 14 Part 1) |
      attestation_id                     |
      receipt_id   ----------------------+
      proposal_id
      approval_id
      result_hash

Each artifact references its predecessor by ID and includes relevant hashes
for integrity verification.

### 3.2 What Hashes Prove

The hash chain provides the following verifiable claims:

1. Proposal integrity: content_hash in receipt matches content_hash in approval,
   proving the proposal executed is the same proposal that was approved.

2. Approval binding: approval_id in receipt references a specific approval,
   proving execution was authorized by that approval.

3. Receipt authenticity: receipt_hash allows verification that the receipt
   has not been modified since creation.

4. Result integrity: result_hash in attestation allows verification that
   the execution result has not been modified since capture.

5. Attestation authenticity: attestation_hash allows verification that the
   attestation has not been modified since creation.

6. Temporal ordering: Timestamps in receipt (before) and attestation (after)
   bracket the execution window.

### 3.3 What Hashes Do NOT Prevent

EXPLICIT STATEMENT: Hashes provide detection, not prevention.

The hash chain does NOT:
- Prevent execution of a modified proposal (detection only)
- Prevent reuse of an approval (detection requires external comparison)
- Prevent execution on unauthorized machines (context is recorded, not enforced)
- Prevent execution by unauthorized operators (identity is recorded, not enforced)
- Prevent deletion of artifacts (immutability is out of scope)
- Prevent modification of artifacts before hash computation
- Guarantee artifacts were created (failure tolerance allows missing artifacts)

The observability layer is evidence-based. It enables detection and forensic
analysis but does not enforce constraints.

--------------------------------------------------------------------------------

## 4. Failure Model

### 4.1 Receipt Creation Failure

Scenario: Execution Receipt cannot be created before adapter execution.

Possible causes:
- Filesystem write failure (permissions, disk full, path invalid)
- JSON serialization error (should not occur with valid data)
- Hash computation error (should not occur with valid algorithm)

Behavior:
- Log the failure reason internally
- Set a flag indicating receipt was not created
- Proceed with adapter execution
- Include warning in final execution result

Execution result includes:
- warning: "Execution receipt could not be created: <reason>"
- receipt_created: false

Rationale: The operator requested execution. Failing to record evidence
of that execution does not change the operator's authorization to execute.

### 4.2 Attestation Creation Failure

Scenario: Result Attestation cannot be created after adapter execution.

Possible causes:
- Filesystem write failure (permissions, disk full, path invalid)
- JSON serialization error (should not occur with valid data)
- Hash computation error (should not occur with valid algorithm)
- Receipt was not created (attestation still attempted with null receipt_id)

Behavior:
- Log the failure reason internally
- Include warning in execution result
- Return execution result normally

Execution result includes:
- warning: "Result attestation could not be created: <reason>"
- attestation_created: false

Rationale: The execution has already completed. Failing to record evidence
of that execution does not change what occurred.

### 4.3 Warning Surfacing

Warnings from the observability layer are surfaced in the execution result
JSON under a dedicated warnings array. Each warning includes:
- source: "observability"
- message: Human-readable description
- artifact: Which artifact was affected (receipt or attestation)

Warnings do NOT:
- Change the exit code of exec run
- Cause exec run to return failure status
- Appear on stderr (JSON output only)

### 4.4 Partial Evidence State

After execution with observability failures, the evidence state may be:

| Receipt | Attestation | Evidence State |
|---------|-------------|----------------|
| Created | Created     | Complete       |
| Created | Failed      | Partial (execution occurred, outcome unknown to evidence) |
| Failed  | Created     | Partial (outcome known, intent not recorded beforehand) |
| Failed  | Failed      | None (execution occurred but no evidence recorded) |

All four states are valid outcomes. The execution result itself serves as
primary evidence; the observability artifacts are supplementary.

--------------------------------------------------------------------------------

## 5. Threat Coverage

### 5.1 Phase 13 Risks Addressed by Detection

The following Phase 13 risks are DETECTED (not prevented) by this phase:

R3. INCOMPLETE AUDIT TRAIL (Phase 13 Section 1.1)
- Detection: Execution Receipt and Result Attestation provide persistent
  evidence of execution intent and outcome.
- Limitation: Detection depends on artifacts being created and retained.
  Artifact deletion is not prevented.

R4. MISSING EXECUTION CONTEXT (Phase 13 Section 1.1)
- Detection: Execution Context in Receipt captures hostname, username,
  working directory, and environment variable names.
- Limitation: Context is recorded but not verified against expectations.

R6. RESULT TAMPERING (Phase 13 Section 1.1)
- Detection: result_hash in Attestation allows verification of result
  integrity by comparing against the hash.
- Limitation: Tampering before hash computation is not detectable.
  Attestation itself could be modified if not externally protected.

### 5.2 Phase 13 Risks Partially Detected

The following Phase 13 risks are PARTIALLY DETECTED:

R5. OPERATOR ACCOUNTABILITY GAP (Phase 13 Section 1.1)
- Partial detection: executed_by field records who ran exec run.
- Limitation: Identity is captured from environment variables, not
  authenticated. Spoofing executed_by is trivial.
- Full mitigation requires identity verification (out of scope).

### 5.3 Phase 13 Risks NOT Addressed

The following Phase 13 risks are NOT ADDRESSED in this phase:

R1. APPROVAL REPLAY (Phase 13 Section 1.1)
- Not addressed: No mechanism checks whether an approval has been used before.
- Rationale: Replay prevention requires state comparison across executions.
  This is an enforcement mechanism, not observability.
- Deferred to: Phase 15 or later.

R2. STALE APPROVALS (Phase 13 Section 1.1)
- Not addressed: No mechanism checks approval age or validity window.
- Rationale: Expiration enforcement would block execution based on time.
  This is an enforcement mechanism, not observability.
- Deferred to: Phase 15 or later.

### 5.4 Coverage Summary Table

| Risk | Phase 13 ID | Coverage | Notes |
|------|-------------|----------|-------|
| Approval Replay | R1 | Not addressed | Enforcement mechanism |
| Stale Approvals | R2 | Not addressed | Enforcement mechanism |
| Incomplete Audit Trail | R3 | Detected | Artifacts created |
| Missing Execution Context | R4 | Detected | Context captured |
| Operator Accountability Gap | R5 | Partially detected | Identity recorded, not verified |
| Result Tampering | R6 | Detected | Hash enables verification |

--------------------------------------------------------------------------------

## 6. Explicit Non-Goals

Phase 14 Part 1 explicitly does NOT include:

NG1. No approval expiration.
     Approvals do not expire. Time-based validity checking is not implemented.
     Approvals created in Phase 12 remain valid indefinitely for execution.

NG2. No replay prevention.
     Approvals may be used multiple times. No mechanism tracks or prevents
     reuse of the same approval for multiple executions.

NG3. No operator identity enforcement.
     The executed_by field is recorded but not verified. Any value from the
     environment is accepted. Identity spoofing is not prevented.

NG4. No environment binding.
     Approvals are not bound to specific hosts, users, or directories.
     An approval created on machine A can be used on machine B.

NG5. No filesystem immutability guarantees.
     Observability artifacts are written to the filesystem with standard
     permissions. Deletion or modification is not prevented by AICtrl.

NG6. No network reporting.
     All observability artifacts are local files. No network transmission,
     no remote logging, no telemetry, no phone-home behavior.

NG7. No blocking on observability failure.
     Execution proceeds even if receipt or attestation creation fails.
     Observability failures produce warnings, not errors.

NG8. No cryptographic signing of artifacts.
     Receipts and attestations include hashes but are not signed.
     Signing would require key management infrastructure (out of scope).

NG9. No policy evaluation.
     No policies are evaluated during execution. The observability layer
     records evidence; it does not make authorization decisions.

NG10. No modification of Phase 12 behavior.
      The propose, review, approve, and run commands retain their Phase 12
      semantics. Observability is additive, not behavioral.

--------------------------------------------------------------------------------

## 7. Phase Boundary Statement

### 7.1 Enforcement Deferral

EXPLICIT STATEMENT:

All enforcement mechanisms belong to Phase 15 or later.

Phase 14 Part 1 is strictly observability. The following capabilities are
explicitly deferred:

- Approval expiration enforcement (Phase 15+)
- Replay prevention enforcement (Phase 15+)
- Operator identity verification (Phase 15+)
- Context binding enforcement (Phase 15+)
- Artifact immutability enforcement (Phase 15+)

### 7.2 Phase 14 Part 1 Completion Criteria

Phase 14 Part 1 design is complete when:

C1. This design document has been reviewed and approved.

C2. Artifact model aligns with Phase 13 lifecycle definitions.

C3. Failure model ensures execution is never blocked by observability.

C4. Threat coverage mapping is accepted by stakeholders.

C5. Non-goals are confirmed as intentional scope exclusions.

### 7.3 Implementation Prerequisites

Before implementation of Phase 14 Part 1 may proceed:

P1. Phase 13 design must be approved.

P2. This Phase 14 Part 1 design must be approved.

P3. Artifact storage location convention must be defined.

P4. Warning surfacing format must be confirmed.

### 7.4 Phase 14 Part 2 Preview

Phase 14 Part 2 (future) may include:

- Artifact query commands (list receipts, list attestations)
- Artifact verification commands (verify receipt, verify attestation)
- Evidence chain validation command
- Artifact retention policy configuration

Phase 14 Part 2 would NOT include enforcement mechanisms.

--------------------------------------------------------------------------------

## 8. Open Questions for Review

Q1. Where should observability artifacts be stored?
    - Same directory as proposal/approval?
    - Dedicated artifacts directory?
    - Configurable location?

Q2. Should artifact filenames include timestamps or only IDs?
    - ID only: receipt-<receipt_id>.json
    - Timestamped: receipt-<timestamp>-<receipt_id>.json

Q3. Should result_summary truncation be configurable?
    - Fixed 256 characters?
    - Configurable via environment variable?
    - No truncation (full result in attestation)?

Q4. Should missing receipt affect attestation creation?
    - Attestation created with null receipt_id?
    - Attestation skipped if receipt failed?
    - Attestation created with warning about missing receipt?

Q5. Should observability be opt-out?
    - Always create artifacts (current design)?
    - Environment variable to disable?
    - Flag to disable (--no-observability)?

--------------------------------------------------------------------------------

## 9. Document History

Draft 1.0 (2026-02-04):
- Initial design document
- Defines Execution Receipt and Result Attestation artifacts
- Specifies evidence chain linkage
- Documents failure model with execution-first priority
- Maps Phase 13 risk coverage
- Enumerates explicit non-goals
- Establishes phase boundary with enforcement deferral

--------------------------------------------------------------------------------

END OF DOCUMENT
