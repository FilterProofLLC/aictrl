# Phase 15.3: Enforcement Rollout and Activation Policy

Status: DESIGN ONLY - No Implementation

Date: 2026-02-05

---

## 1. Purpose

This document defines the policy for activating Phase 15 location enforcement.
It specifies who should enable enforcement, when it should be enabled, and how
rollout should proceed safely.

Phase 15 enforcement capability was implemented in Phases 15.1 and 15.2, but
capability is intentionally separated from activation. This separation exists
because:

1. **Discovered Failure Mode**: Development work was inadvertently performed
   in a git submodule at `~/work/AIOS/tools/aictrl` rather than the canonical
   standalone clone at `~/work/aictrl`. This caused uncommitted artifact drift
   and confusion about the authoritative working location.

2. **Safety by Default**: Enforcement that breaks existing workflows without
   explicit opt-in violates user trust and governance principles.

3. **Observability First**: Phase 14 established that observability (warnings)
   must precede enforcement (denials), allowing users to understand impact
   before experiencing blocking behavior.

This document answers:
- Who should enable enforcement
- When enforcement should be enabled
- How enforcement should roll out safely
- What guarantees exist when enforcement is OFF
- How future defaults may change (without doing so now)

---

## 2. Current State (As Of This Phase)

### 2.1 Enforcement Code Status

Enforcement code is **fully implemented** and **merged**:

| Phase | Error Code | Description | Status |
|-------|------------|-------------|--------|
| 15.1 | AICTRL-7001 | Non-canonical working location | Implemented |
| 15.1 | AICTRL-7002 | Submodule execution detected | Implemented |
| 15.2 | AICTRL-7003 | Origin remote mismatch | Implemented |
| 15.2 | AICTRL-7004 | Detached HEAD state | Implemented |
| 15.2 | AICTRL-7005 | Symlinked working path | Implemented |

### 2.2 Default Behavior

The current default behavior is **warn-only**:

- All location violations emit Phase 14 observability warnings
- No execution is blocked
- Exit codes remain unchanged (enforcement does not trigger)
- Baseline artifacts are unaffected

### 2.3 CI Environment Exemption

CI environments are **always exempt** from enforcement, regardless of flag state:

- Detection via `GITHUB_ACTIONS`, `CI`, `GITLAB_CI`, `JENKINS_URL`, etc.
- Exemption is permanent and not configurable
- Rationale: CI runners legitimately use non-canonical paths

### 2.4 Enforcement Activation

No enforcement is active unless **explicitly enabled** via environment variable.

---

## 3. Activation Mechanism

### 3.1 Environment Variable

Enforcement is controlled by `AICTRL_ENFORCE_LOCATION`:

| Value | Behavior |
|-------|----------|
| unset | Warn-only (Phase 14 observability) |
| `""` (empty) | Warn-only |
| `0` | Warn-only |
| `false` | Warn-only |
| `1` | **Enforce** - deny on violation (exit code 2) |
| `true` | **Enforce** - deny on violation (exit code 2) |

### 3.2 No Auto-Enablement

**EXPLICIT STATEMENT**: Enforcement is NEVER automatically enabled.

The following will NOT trigger enforcement:
- Specific aictrl versions
- Specific operating systems
- Specific shell environments
- Detection of "production" vs "development" context
- Time-based activation
- Feature flag services
- Remote configuration

Enforcement requires a human operator to explicitly set the environment variable.

### 3.3 Precedence Rules

1. CI environment detected -> **Exempt** (regardless of flag)
2. `AICTRL_ENFORCE_LOCATION=1` or `true` -> **Enforce**
3. All other cases -> **Warn-only**

---

## 4. Intended Users

### 4.1 Local Developers

- **Recommended**: Keep enforcement OFF during normal development
- **Optional**: Enable enforcement to validate working location hygiene
- **Use case**: Catching accidental work in submodules or forks

### 4.2 CI Systems

- **Status**: Always exempt from enforcement
- **Rationale**: CI runners use ephemeral paths that will never match canonical
- **Observability**: Warnings are still emitted for diagnostic purposes

### 4.3 Release Pipelines

- **Recommended**: Enable enforcement for release artifact generation
- **Rationale**: Ensures releases are built from canonical location
- **Benefit**: Prevents accidental release from fork or submodule

### 4.4 Security-Sensitive Environments

- **Recommended**: Enable enforcement
- **Rationale**: Ensures execution context is verified
- **Benefit**: Prevents execution from unauthorized repository copies

---

## 5. Recommended Rollout Phases

### Phase A: Observability Only (Current)

**Status**: Active

- Enforcement code is deployed
- Default behavior is warn-only
- Users observe warnings in output
- No workflow disruption
- Duration: Until sufficient observability data is collected

### Phase B: Opt-In Enforcement for Developers

**Status**: Available now (requires explicit activation)

- Individual developers may enable `AICTRL_ENFORCE_LOCATION=1`
- Enables personal workflow validation
- Provides feedback on enforcement impact
- No organizational mandate

### Phase C: CI Optional Enforcement

**Status**: Deferred (CI remains exempt)

- Would allow CI to opt into enforcement
- Requires CI-specific canonical path configuration
- Not currently planned
- Would require design amendment

### Phase D: Future Default Enforcement

**Status**: Explicitly deferred

- Would change default from warn-only to enforce
- **REQUIRES**: Major version increment
- **REQUIRES**: Migration documentation
- **REQUIRES**: Deprecation notice in prior minor version
- **NOT PART OF THIS PHASE OR ANY PLANNED PHASE**

---

## 6. Non-Goals

This policy explicitly excludes:

1. **No Silent Activation**
   - Enforcement will never activate without explicit user action
   - No "surprise" blocking behavior

2. **No Breaking Default Behavior**
   - Default remains warn-only indefinitely
   - Change requires major version and explicit migration

3. **No Environment Auto-Detection Enforcement**
   - Detection of "production" environment does not trigger enforcement
   - Detection of "security" context does not trigger enforcement
   - Only explicit `AICTRL_ENFORCE_LOCATION=1` triggers enforcement

4. **No Backward-Incompatible Defaults**
   - Users upgrading aictrl will not experience new blocking behavior
   - Existing workflows continue to function

---

## 7. Failure Handling Philosophy

### 7.1 Deterministic Denial

When enforcement is enabled and a violation is detected:

- Exit code is **always** 2 (policy denial)
- Error message is **always** emitted
- Error code is **always** included (AICTRL-7001 through 7005)
- No probabilistic or sampled enforcement

### 7.2 Explicit Error Codes

Each violation has a unique, stable error code:

| Code | Meaning |
|------|---------|
| AICTRL-7001 | Non-canonical working location |
| AICTRL-7002 | Submodule execution detected |
| AICTRL-7003 | Origin remote mismatch |
| AICTRL-7004 | Detached HEAD state |
| AICTRL-7005 | Symlinked working path |

Error codes are:
- Stable across versions
- Documented in error taxonomy
- Suitable for programmatic handling

### 7.3 No Partial Enforcement

Enforcement is all-or-nothing:

- Either warn-only (all checks produce warnings)
- Or enforce (first violation triggers denial)
- No per-check enable/disable flags
- No severity-based enforcement

---

## 8. Versioning Guidance

### 8.1 Capability vs Behavior

| Change Type | Version Impact |
|-------------|----------------|
| Add new detection (e.g., AICTRL-7006) | Minor version |
| Improve detection accuracy | Patch version |
| Change default from warn to enforce | **Major version** |
| Remove enforcement capability | Major version |

### 8.2 Default Enforcement Change

Changing the default behavior from warn-only to enforce would require:

1. **Major version increment** (e.g., 2.0.0)
2. **Prior deprecation notice** in at least one minor release
3. **Migration documentation** explaining how to preserve warn-only
4. **Explicit changelog entry** describing the breaking change

**EXPLICIT STATEMENT**: No current plan exists for this change.

---

## 9. Operational Guidance

### 9.1 Warn-Only Execution (Default)

To run with default warn-only behavior:

    aictrl <command>

Or explicitly:

    AICTRL_ENFORCE_LOCATION=0 aictrl <command>

Observability warnings will appear in output if violations are detected.

### 9.2 Enforced Execution

To run with enforcement enabled:

    AICTRL_ENFORCE_LOCATION=1 aictrl <command>

If a violation is detected:
- Exit code will be 2
- Error message will include the specific violation code
- Hint will suggest remediation

### 9.3 Checking Current Mode

The enforcement mode is reflected in command output:
- Warning artifacts include `"source": "observability"`
- Denial responses include `"enforcement": {"phase": 15, ...}`

---

## 10. Backward Compatibility Guarantees

### 10.1 Phase 14 Behavior Preserved

When enforcement is OFF (default):

- All location checks emit warnings only
- Warning format matches Phase 14 observability specification
- Warning artifacts include: source, message, artifact, code
- No exit code changes

### 10.2 Phase 12 Invariants Preserved

Regardless of enforcement mode:

- Baseline artifacts are not modified by location checks
- Invariant checking continues to function
- Governance model is not affected
- AI prohibition remains in effect (INV-004, INV-005, INV-007)

### 10.3 Baseline Artifacts Unaffected

When enforcement is OFF:

- Baseline generation produces identical artifacts
- Baseline verification produces identical results
- No location-related fields are added to baseline

---

## 11. Phase Boundary Statement

### 11.1 Scope of Phase 15.3

Phase 15.3 defines **policy only**:

- Documents activation mechanism
- Specifies rollout guidance
- Establishes versioning rules
- Provides operational examples

### 11.2 Implementation Status

All implementation is complete in prior phases:

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 15.1 | AICTRL-7001, 7002 detection and enforcement | Merged |
| 15.2 | AICTRL-7003, 7004, 7005 detection and enforcement | Merged |
| 15.3 | Rollout policy (this document) | This document |

### 11.3 No Further Code Changes

**EXPLICIT STATEMENT**: Phase 15.3 introduces no code changes.

- No runtime modifications
- No test additions
- No baseline changes
- No version bumps
- No tag creation

---

## 12. Document History

### 12.1 Related Documents

| Document | Relationship |
|----------|--------------|
| PHASE_13_POST_EXECUTION_GOVERNANCE_DESIGN.md | Established enforcement deferral to Phase 15+ |
| PHASE_14_PART_1_OBSERVABILITY_DESIGN.md | Established observability-before-enforcement principle |
| PHASE_15_ENFORCEMENT_DESIGN.md | Defined enforcement error taxonomy and decision flow |

### 12.2 Phase 15 Document Chain

1. **PHASE_15_ENFORCEMENT_DESIGN.md** - Threat model, error codes, decision flowchart
2. **Phase 15.1 PR** - Implemented AICTRL-7001, 7002
3. **Phase 15.2 PR** - Implemented AICTRL-7003, 7004, 7005
4. **PHASE_15_3_ENFORCEMENT_ROLLOUT_POLICY.md** - This document (activation policy)

---

## 13. Summary

Phase 15 location enforcement is:

- **Implemented**: All detection and enforcement code is merged
- **Available**: Users may enable via `AICTRL_ENFORCE_LOCATION=1`
- **Off by default**: Warn-only behavior unless explicitly enabled
- **CI exempt**: CI environments are never blocked
- **Stable**: Error codes and exit codes are deterministic
- **Safe**: No auto-enablement, no silent activation, no breaking changes

Future default enforcement (Phase D) is explicitly deferred and would require
a major version increment with full migration documentation.

---

*End of Document*
