# Phase 15 Design: Location Enforcement Guardrails

Status: DESIGN ONLY - No Implementation
Version: Draft 1.0
Date: 2026-02-05

## Document Purpose

This document describes the design goals, threat model, enforcement policy,
and rollout plan for Phase 15 of AICtrl. Phase 15 introduces deterministic
enforcement guardrails for working-copy location, building on the observability
signals established in Phase 14.

CRITICAL: This document is for design review only. No enforcement logic,
no error codes, no exit code changes, no runtime modifications are introduced
by this document. Implementation requires approval of this design.

--------------------------------------------------------------------------------

## 1. Motivation

### 1.1 Discovered Failure Mode

During routine operations in early February 2026, a forensic trace revealed
that all aictrl development work (Phases 9 through 14, commits for PRs #3
through #12, tags v1.2.0 through v1.6.0) had been performed from within a
git submodule embedded in the AIOS repository:

    /home/filterprooftravis/work/AIOS/tools/aictrl

This is NOT the canonical standalone working copy. The submodule working tree
had accumulated:

- 3 modified tracked files (baseline attestation, manifest, spec-coverage)
- 3 untracked generated files (timestamped baseline results)
- 1 stash entry (superseded earlier attestation draft)
- A stale submodule pointer in AIOS (pinned at v1.1.0, actual HEAD at v1.6.0+4)

None of these artifacts had been committed. The submodule's HEAD had advanced
18 commits beyond what the AIOS parent repository recorded.

This failure mode demonstrates that without location enforcement:
- Work can silently occur in non-canonical locations
- Artifacts can accumulate without being committed
- Submodule pointers can drift without detection
- Forensic traceability is compromised

### 1.2 Why Observability Alone Is Insufficient

Phase 14 introduced observability: the ability to DETECT and RECORD the
execution environment, including working directory. However, Phase 14
explicitly does not block execution or surface enforcement denials.

From Phase 14 Part 1 Design, Section 7.1:

    "All enforcement mechanisms belong to Phase 15 or later."

Phase 15 fulfills this contract by defining when and how location-related
signals transition from passive observation to active enforcement.

### 1.3 Relationship to Phase 13 Risks

Phase 13 identified six governance risks (R1 through R6). Phase 15 directly
addresses:

- R4 (MISSING EXECUTION CONTEXT): Phase 14 records working_directory in
  execution receipts. Phase 15 enforces that this directory matches the
  canonical location or an explicitly approved alternate.

- R5 (OPERATOR ACCOUNTABILITY GAP): When work occurs in an untracked
  location, operator actions are harder to attribute. Enforcing a canonical
  location creates a single auditable locus of activity.

Phase 15 also introduces a new risk category not enumerated in Phase 13:

- R7 (LOCATION DRIFT): Development occurring across multiple working copies
  without coordination causes artifact divergence, stale submodule pointers,
  and uncommitted work that may never be discovered.

### 1.4 Explicit Non-Goals

NG1. Phase 15 will NOT expand execution capabilities.
     No new adapters, actions, or relaxation of Phase 12 gates.

NG2. Phase 15 will NOT introduce network operations.
     All enforcement is local path comparison. No remote validation.

NG3. Phase 15 will NOT modify Phase 12 approval or execution flow.
     Existing propose/review/approve/run semantics are unchanged.

NG4. Phase 15 will NOT modify Phase 14 observability behavior.
     Receipts and attestations continue to be created regardless of
     enforcement outcome. Enforcement is additive.

NG5. Phase 15 will NOT enforce on observability-only operations.
     Read-only commands (version, status, doctor, evidence export)
     will NEVER be blocked by location enforcement.

NG6. Phase 15 will NOT modify existing error code ranges.
     New error codes occupy a dedicated range (see Section 5).

NG7. Phase 15 will NOT remove or alter existing artifacts.
     Baseline results, attestations, and evidence bundles are untouched.

--------------------------------------------------------------------------------

## 2. Threat Model

### 2.1 Failure Case Taxonomy

The following failure cases motivate Phase 15 enforcement:

F1. SUBMODULE WORKTREE WITH DIRTY STATE

    Scenario: aictrl is checked out as a git submodule inside another
    repository (e.g., AIOS). Work performed in the submodule accumulates
    modified and untracked files that are not visible from the parent
    repository's git status.

    Evidence: This is the exact failure mode discovered in February 2026.
    The submodule at ~/work/AIOS/tools/aictrl had 6 dirty files and a
    stash entry. The parent AIOS repo showed only "modified: tools/aictrl"
    as a single submodule pointer change.

    Risk: Uncommitted work is invisible to standard workflows.
    Artifacts may never be committed or may be lost on submodule reset.

    Detection signal: .git is a file (not a directory) containing a
    gitdir: pointer to the parent repository's .git/modules/ tree.

F2. ALTERNATE CLONES IN UNEXPECTED LOCATIONS

    Scenario: A developer clones aictrl into ~/Projects/aictrl,
    /tmp/aictrl-test, or another ad-hoc location for experimentation.
    Work performed there diverges from the canonical copy.

    Risk: Commits pushed from alternate clones may have different
    local configurations (user.name, user.email, hooks). Artifacts
    generated in alternate locations are not discoverable by standard
    tooling that assumes the canonical path.

    Detection signal: realpath(CWD) does not match realpath(CANONICAL_PATH).

F3. SYMLINKED PATHS MASKING REAL LOCATION

    Scenario: A symlink such as ~/aictrl -> ~/work/aictrl makes the
    repository accessible from multiple paths. Tools that resolve paths
    differently may disagree on the working location, causing confusion
    in audit trails.

    Risk: Execution receipts may record the symlink path instead of the
    real path, making forensic correlation harder. Two receipts from the
    "same" repository may show different working_directory values.

    Detection signal: os.path.realpath(CWD) differs from CWD itself,
    indicating symlink traversal. After resolution, the realpath may
    or may not match the canonical location.

F4. DETACHED HEAD OR MISMATCHED ORIGIN REMOTES

    Scenario: A working copy exists at the canonical path but has been
    configured with a fork remote (e.g., origin points to a personal
    fork instead of FilterProofLLC/aictrl), or HEAD is detached and
    not tracking any branch.

    Risk: Commits pushed from this state may target the wrong repository.
    Baseline runs may report incorrect git provenance (wrong remote URL,
    no branch name). Tags may not correspond to the official release.

    Detection signal: git remote get-url origin does not match the
    expected canonical remote URL. git symbolic-ref HEAD fails (detached).

F5. CI RUNNERS VS LOCAL EXECUTION DIFFERENCES

    Scenario: CI pipelines (GitHub Actions, GitLab CI) check out the
    repository into ephemeral directories (/home/runner/work/aictrl/aictrl
    or /builds/group/aictrl). These paths never match the canonical
    local development path.

    Risk: Strict path enforcement would break CI. CI environments are
    legitimate execution contexts that must be explicitly accommodated.

    Detection signal: CI environment variables are present (CI,
    GITHUB_ACTIONS, GITLAB_CI, etc.), as already detected by
    detect_execution_context() in aictrl/util/invariants.py.

F6. MULTIPLE CANONICAL-LOOKING COPIES

    Scenario: Both ~/work/aictrl and ~/work/AIOS/tools/aictrl exist and
    both have the same remote URL and recent commits. A developer switches
    between them without realizing they are separate working trees.

    Risk: Changes made in one copy are not reflected in the other. Git
    operations (branch, stash, worktree state) diverge. This is exactly
    the failure mode that prompted Phase 15 design.

    Detection signal: Multiple directories on the same machine resolve
    to different filesystem paths but share the same remote URL.
    Detection requires enumeration beyond the current working directory
    (out of scope for per-invocation checks, but noted for future work).

F7. WORKTREE OR SPARSE-CHECKOUT CONFIGURATIONS

    Scenario: git worktree add creates additional working trees linked
    to the same repository. sparse-checkout may cause partial file
    visibility, leading to incomplete baseline runs.

    Risk: Worktrees share the same .git object store but have independent
    working trees and HEAD pointers. Operations in a worktree may not
    be visible from the main working tree.

    Detection signal: .git is a file containing gitdir: pointing to a
    worktrees/ subdirectory within the main repository's .git/.
    This is structurally similar to submodule detection (F1).

### 2.2 Threat Coverage Matrix

| Failure Case | Phase 14 (Detect) | Phase 15 (Enforce) |
|---|---|---|
| F1: Submodule dirty state | working_directory in receipt | DENY or WARN |
| F2: Alternate clone | working_directory in receipt | DENY or WARN |
| F3: Symlinked path | working_directory in receipt | WARN (realpath comparison) |
| F4: Detached HEAD / wrong remote | Not detected | WARN |
| F5: CI runner path | context detected as AIOS_CI | ALLOW (CI exemption) |
| F6: Multiple copies | Not detected per-invocation | WARN (advisory) |
| F7: Worktree / sparse-checkout | Not detected | WARN |

--------------------------------------------------------------------------------

## 3. Policy Definitions

### 3.1 Canonical Path Invariant

The canonical working location for aictrl is:

    ~/work/aictrl

Formally:

    realpath(os.path.expanduser("~/work/aictrl"))

The enforcement check compares:

    realpath(CWD) == realpath(CANONICAL_PATH)

where CWD is the current working directory at the time of the aictrl
invocation, or the git repository root if determinable.

### 3.2 Canonical Remote Invariant

The canonical git remote origin URL is one of:

    https://github.com/FilterProofLLC/aictrl.git
    git@github.com:FilterProofLLC/aictrl.git

Enforcement verifies that the origin remote URL matches one of these
patterns. Mismatches indicate a fork, mirror, or misconfigured clone.

### 3.3 Approved Alternate Locations

Phase 15 recognizes that enforcement must accommodate legitimate
non-canonical paths. The following are automatically approved:

    APPROVED CONTEXT: CI Environment
    Condition: detect_execution_context() returns AIOS_CI
    Rationale: CI runners use ephemeral paths outside developer control.
    Action: ALLOW (skip path enforcement entirely)

For other cases, an operator may explicitly approve a non-canonical
location by setting an environment variable:

    AICTRL_APPROVED_LOCATION=<path>

When set, enforcement compares:

    realpath(CWD) == realpath(AICTRL_APPROVED_LOCATION)

If this matches, the alternate location is treated as canonical for
that invocation. The approved location is recorded in the execution
receipt for traceability.

### 3.4 Submodule Policy

When execution occurs inside a git submodule:

- The submodule status is always recorded (observability, Phase 14)
- If enforcement is enabled, submodule execution emits DENY with
  error code AICTRL-7002
- The denial message includes the parent repository path
- The denial does NOT clean, modify, or alter the submodule state

### 3.5 What Enforcement Does NOT Do

Enforcement is a gate check at invocation time. It does NOT:
- Modify the filesystem (no file creation, deletion, or moves)
- Alter git state (no checkout, reset, fetch, or pull)
- Contact any remote service
- Modify environment variables
- Write enforcement decisions to persistent storage (Phase 14
  observability handles artifact creation independently)

--------------------------------------------------------------------------------

## 4. Enforcement Decision Flowchart

    aictrl invoked
        |
        v
    Is AICTRL_ENFORCE_LOCATION set to "1" or "true"?
        |
        +-- NO --> Phase 14 behavior: detect + record only
        |          (emit observability warnings if non-canonical)
        |          Result: WARN-ONLY
        |
        +-- YES --> Continue to enforcement checks
                |
                v
            Is execution context CI? (detect_execution_context() == AIOS_CI)
                |
                +-- YES --> Result: ALLOW (CI exemption)
                |
                +-- NO --> Continue
                        |
                        v
                    Is AICTRL_APPROVED_LOCATION set?
                        |
                        +-- YES --> Does realpath(CWD) == realpath(APPROVED)?
                        |               |
                        |               +-- YES --> Result: ALLOW
                        |               |
                        |               +-- NO --> Result: DENY (AICTRL-7001)
                        |
                        +-- NO --> Continue
                                |
                                v
                            Does realpath(CWD) == realpath(CANONICAL_PATH)?
                                |
                                +-- YES --> Is .git a file (submodule)?
                                |               |
                                |               +-- YES --> Result: DENY (AICTRL-7002)
                                |               |
                                |               +-- NO --> Is origin remote canonical?
                                |                               |
                                |                               +-- YES --> Result: ALLOW
                                |                               |
                                |                               +-- NO --> Result: DENY (AICTRL-7003)
                                |
                                +-- NO --> Is .git a file (submodule)?
                                                |
                                                +-- YES --> Result: DENY (AICTRL-7002)
                                                |
                                                +-- NO --> Result: DENY (AICTRL-7001)

All DENY results:
- Return a deterministic error code (see Section 5)
- Return exit code 2 (policy denial, consistent with Phase 12)
- Include the detected path, expected path, and remediation hint in JSON output
- Do NOT suppress Phase 14 observability (receipt/attestation still created if possible)

All ALLOW results:
- Execution proceeds normally
- No output modification
- Phase 14 observability operates independently

All WARN-ONLY results:
- Execution proceeds normally
- Observability warnings included in execution result (if applicable)
- No exit code change

--------------------------------------------------------------------------------

## 5. Error Taxonomy

### 5.1 Error Code Range

Phase 15 uses the AICTRL-7xxx range for location enforcement errors.
This range is currently unoccupied in the error code taxonomy defined
in aictrl/util/errors.py.

### 5.2 Error Code Definitions

    AICTRL-7001  LOCATION_NON_CANONICAL
        Condition: realpath(CWD) does not match realpath(CANONICAL_PATH)
                   and no approved alternate location matches.
        Message:   "Non-canonical working location detected"
        Detail:    Includes actual_path and expected_path fields.
        Exit code: 2

    AICTRL-7002  LOCATION_SUBMODULE_DETECTED
        Condition: Current working copy is a git submodule (the .git
                   entry is a file, not a directory).
        Message:   "Execution from git submodule is not permitted"
        Detail:    Includes parent_repo path and submodule_path fields.
        Exit code: 2

    AICTRL-7003  LOCATION_REMOTE_MISMATCH
        Condition: git remote get-url origin does not match any
                   canonical remote URL pattern.
        Message:   "Origin remote does not match canonical repository"
        Detail:    Includes actual_remote and expected_remotes fields.
        Exit code: 2

    AICTRL-7004  LOCATION_DETACHED_HEAD
        Condition: HEAD is detached (git symbolic-ref HEAD fails).
        Message:   "Detached HEAD state detected"
        Detail:    Includes current HEAD commit hash.
        Exit code: 2
        Note:      This is a WARN-level signal in initial rollout.
                   May be promoted to DENY in future phases.

    AICTRL-7005  LOCATION_SYMLINK_DETECTED
        Condition: CWD differs from realpath(CWD), indicating symlink
                   traversal. After resolution, path may or may not
                   match canonical location.
        Message:   "Symlinked path detected"
        Detail:    Includes symlink_path and resolved_path fields.
        Exit code: 2
        Note:      This is a WARN-level signal in initial rollout.
                   Enforcement applies only if resolved path also
                   fails the canonical check.

### 5.3 Exit Code Mapping

| Exit Code | Meaning | Phase 15 Usage |
|---|---|---|
| 0 | Success | Enforcement passed, execution proceeds |
| 1 | Runtime failure | Not used by enforcement |
| 2 | Policy denial | All AICTRL-7xxx enforcement denials |

This is consistent with Phase 12, which uses exit code 2 for all
policy-related denials (adapter not in allowlist, dangerous gate
required, hash mismatch, etc.).

### 5.4 JSON Output Structure for Denials

When enforcement denies execution, the JSON output follows the
existing error structure from aictrl/util/errors.py:

    {
      "success": false,
      "error": "<human-readable message>",
      "error_code": "AICTRL-7001",
      "hint": "<remediation guidance>",
      "enforcement": {
        "phase": 15,
        "check": "canonical_path",
        "actual_path": "/home/user/work/AIOS/tools/aictrl",
        "expected_path": "/home/user/work/aictrl",
        "is_submodule": true,
        "parent_repo": "/home/user/work/AIOS",
        "ci_detected": false,
        "approved_location": null
      },
      "exit_code": 2
    }

The "enforcement" block provides structured data for programmatic
consumption. All fields are ASCII strings, booleans, integers, or null.

--------------------------------------------------------------------------------

## 6. Backwards-Compatibility Guarantees

### 6.1 Baseline Behavior When Guardrail Passes

When enforcement is disabled (default) or when the canonical path check
passes, aictrl behavior is IDENTICAL to current (Phase 14) behavior:

- All CLI commands produce the same output
- All exit codes are unchanged
- All baseline tests continue to pass
- All attestation schemas are unchanged
- Phase 12 invariants are fully preserved:
  - Approval binding (approval_id must match proposal_id)
  - Content hash re-verification at execution time
  - Adapter allowlist (default-deny)
  - Dangerous flag requirement at both propose and run time

### 6.2 Phase 12 Invariants Remain Intact

Phase 15 enforcement is evaluated BEFORE Phase 12 execution checks.
If enforcement denies execution, Phase 12 checks are never reached.
If enforcement allows execution, Phase 12 checks proceed exactly as
they do today, with no modification to:

- Proposal validation (structure, hash, adapter)
- Approval validation (ID binding, content hash)
- Dangerous gate enforcement
- Adapter execution semantics
- Result capture and return

### 6.3 Phase 14 Observability Remains Independent

Phase 14 observability (execution receipts and result attestations)
operates independently of Phase 15 enforcement:

- When enforcement denies execution, Phase 14 does NOT create receipts
  or attestations (because no execution occurred). However, the denial
  itself is structured JSON that serves as an audit record.

- When enforcement allows execution, Phase 14 observability proceeds
  exactly as today, with no field changes or behavioral modifications.

- The Phase 14 warning format is preserved. Phase 15 does NOT add
  warnings to the existing observability_warnings array. Enforcement
  denials use the standard error output path, not the warning path.

### 6.4 No Existing Error Codes Modified

Phase 15 uses a new, dedicated error code range (AICTRL-7xxx).
No existing error codes in ranges 0xxx through 5xxx or 9xxx are
modified, reassigned, or reinterpreted.

--------------------------------------------------------------------------------

## 7. Enforcement Scope

### 7.1 Commands Subject to Enforcement

When enforcement is enabled, the following command categories are
subject to location checks:

    ENFORCED (mutating operations):
    - aictrl exec propose
    - aictrl exec approve
    - aictrl exec run
    - aictrl crypto keygen (requires --dangerous)
    - aictrl crypto sign

    NOT ENFORCED (read-only operations):
    - aictrl version
    - aictrl status
    - aictrl doctor
    - aictrl support-bundle
    - aictrl evidence export
    - aictrl evidence verify
    - aictrl exec adapters
    - aictrl exec boundary
    - aictrl exec readiness
    - aictrl exec review
    - aictrl attest verify
    - aictrl crypto verify
    - aictrl crypto pubkey
    - aictrl authz check
    - aictrl authz policy
    - aictrl demo

Rationale: Read-only operations produce no side effects and should
always be available for diagnostic purposes, regardless of location.
Enforcement targets only operations that create artifacts or mutate
state.

### 7.2 Enforcement Ordering in Execution Pipeline

For aictrl exec run (the most complex command), enforcement is
evaluated at position 0 in the pipeline, before all other checks:

    Position 0: Phase 15 location enforcement (NEW)
    Position 1: Load and validate approval (Phase 12)
    Position 2: Load and validate proposal (Phase 12)
    Position 3: Re-verify content hash (Phase 12)
    Position 4: Validate adapter allowlist (Phase 12)
    Position 5: Validate dangerous flag (Phase 12)
    Position 6: Create execution receipt (Phase 14)
    Position 7: Execute adapter (Phase 12)
    Position 8: Create result attestation (Phase 14)

If enforcement denies at position 0, positions 1-8 are never reached.
The denial is returned as structured JSON with exit code 2.

--------------------------------------------------------------------------------

## 8. Test Strategy (Design Only)

### 8.1 Unit Tests

Unit tests will verify enforcement logic in isolation using mocked
subprocess calls and filesystem state. No actual git operations or
filesystem modifications occur during testing.

    Test: canonical path passes enforcement
    Setup: Mock realpath(CWD) == realpath(CANONICAL_PATH), .git is directory
    Expected: ALLOW

    Test: non-canonical path triggers denial
    Setup: Mock realpath(CWD) == "/tmp/aictrl", enforcement enabled
    Expected: DENY with AICTRL-7001, exit code 2

    Test: submodule detected triggers denial
    Setup: Mock .git as file with gitdir: content, enforcement enabled
    Expected: DENY with AICTRL-7002, exit code 2

    Test: CI context exempts from enforcement
    Setup: Mock CI environment variable present, non-canonical path
    Expected: ALLOW (CI exemption)

    Test: approved alternate location passes enforcement
    Setup: Mock AICTRL_APPROVED_LOCATION set to CWD, enforcement enabled
    Expected: ALLOW

    Test: enforcement disabled falls back to warn-only
    Setup: Mock non-canonical path, AICTRL_ENFORCE_LOCATION not set
    Expected: WARN-ONLY (no denial, execution proceeds)

    Test: origin remote mismatch triggers denial
    Setup: Mock git remote get-url origin returns fork URL
    Expected: DENY with AICTRL-7003, exit code 2

    Test: all error outputs are ASCII-only
    Setup: Mock various paths including Unicode directory names
    Expected: All JSON output contains only ASCII characters

    Test: subprocess timeout does not block execution
    Setup: Mock subprocess.run to raise TimeoutExpired
    Expected: Graceful handling, no crash, no infinite wait

    Test: missing git binary does not crash
    Setup: Mock shutil.which("git") returns None
    Expected: Graceful degradation, enforcement skipped or warned

### 8.2 Integration Tests (Optional)

Integration tests would use temporary directories with real git
repositories to verify end-to-end behavior. These are optional and
should be designed to avoid environmental flakiness:

    Test: real submodule detection
    Setup: Create temp repo with submodule, run detection from submodule
    Expected: is_submodule == true, parent_repo path correct

    Test: real symlink resolution
    Setup: Create temp directory, create symlink, run detection from symlink
    Expected: Symlink detected, realpath resolves correctly

### 8.3 Test Isolation Requirements

All tests MUST:
- Use tmp_path fixtures or tempfile for filesystem operations
- Mock subprocess.run for git commands (no real git operations)
- Mock os.getcwd, os.path.realpath for path comparisons
- Not depend on the existence of ~/work/aictrl on the test machine
- Not depend on network connectivity
- Not depend on specific git configuration
- Run without root privileges
- Complete within 10 seconds per test

--------------------------------------------------------------------------------

## 9. Rollout Plan

### 9.1 Flag-Gated Rollout

Phase 15 enforcement is controlled by a single environment variable:

    AICTRL_ENFORCE_LOCATION=1    # Enable enforcement (DENY on violation)
    AICTRL_ENFORCE_LOCATION=0    # Disable enforcement (WARN-ONLY)
    (unset)                      # Default: WARN-ONLY

The default is WARN-ONLY, meaning Phase 15 enforcement does not change
any existing behavior until explicitly enabled. This allows:

1. Deployment of enforcement code without breaking existing workflows
2. Observation period to collect location signals via Phase 14
3. Explicit opt-in by operators who are ready for enforcement
4. Gradual rollout across teams and CI pipelines

### 9.2 Rollout Phases

    Phase 15a: WARN-ONLY (default after implementation)
    - Enforcement code is deployed
    - AICTRL_ENFORCE_LOCATION defaults to disabled
    - Phase 14 observability records location context
    - Non-canonical locations produce warnings, not denials
    - Duration: minimum 2 weeks observation

    Phase 15b: OPT-IN ENFORCEMENT
    - Operators set AICTRL_ENFORCE_LOCATION=1 to enable
    - Enforcement denials begin for opted-in environments
    - CI pipelines are verified to have CI exemption working
    - Approved alternate locations are documented
    - Duration: until all known workflows are validated

    Phase 15c: DEFAULT ENFORCEMENT (future)
    - AICTRL_ENFORCE_LOCATION default changes to enabled
    - Operators who need non-canonical locations must set
      AICTRL_APPROVED_LOCATION or AICTRL_ENFORCE_LOCATION=0
    - This phase requires a separate design review before activation

### 9.3 Traceability Between Phase 14 and Phase 15

Phase 14 receipts and Phase 15 denials are independently traceable:

    Phase 14 Receipt (observability):
    - Contains execution_context.working_directory
    - Contains execution_context.location (if Phase 14 location
      detection is implemented)
    - Created on every successful execution
    - NOT created when Phase 15 denies execution (no execution occurred)

    Phase 15 Denial (enforcement):
    - Returned as structured JSON with "enforcement" block
    - Contains all detection signals (path, submodule, remote, etc.)
    - Includes error_code and exit_code for programmatic handling
    - The denial output itself serves as the audit record
    - Operators can capture denial JSON for forensic purposes

    Correlation:
    - When enforcement allows execution, the Phase 14 receipt captures
      the same path information that enforcement checked
    - When enforcement denies execution, the denial JSON captures the
      path information with explicit failure reason
    - Both outputs include timestamp_utc for temporal correlation

### 9.4 Rollback Procedure

If enforcement causes unexpected disruption after enablement:

    Immediate mitigation:
    - Unset AICTRL_ENFORCE_LOCATION (reverts to warn-only)
    - OR set AICTRL_ENFORCE_LOCATION=0

    No code rollback required. The enforcement flag gates all behavior.
    Disabling the flag restores pre-Phase-15 behavior completely.

--------------------------------------------------------------------------------

## 10. Phase Boundaries

### 10.1 Phase 15 Completion Criteria

Phase 15 design is complete when:

C1. This design document has been reviewed and approved.

C2. Threat model has been validated against known failure modes.

C3. Error code range (AICTRL-7xxx) has been confirmed unoccupied.

C4. Rollout plan has been accepted by stakeholders.

C5. Backwards-compatibility guarantees have been verified by
    inspection of the enforcement integration point.

C6. Test strategy has been confirmed sufficient for the enforcement
    scope.

### 10.2 Implementation Boundary

EXPLICIT STATEMENT:

Phase 15 in this document is DESIGN ONLY.

No code changes, no CLI modifications, no version bumps, no baseline
test additions, and no error code registrations occur as part of this
design phase. Implementation requires:

P1. Approval of this design document.
P2. A separate implementation PR with code, tests, and evidence.
P3. Verification that all baseline tests continue to pass.
P4. Verification that enforcement is flag-gated and defaults to off.

### 10.3 Phase 16 Preview

Phase 16 (future) may introduce:

- Persistent enforcement audit log (local file recording all
  enforcement decisions over time)
- Multi-repository location policy (supporting approved paths
  via a configuration file instead of a single env var)
- Enforcement for additional signals (branch name policy,
  commit signing requirements, pre-push hooks)
- Integration with aictrl doctor for enforcement health checks

Phase 16 should not introduce any concepts not referenced in this
document's threat model.

### 10.4 Relationship to Prior Phases

| Phase | Role | Relationship to Phase 15 |
|---|---|---|
| Phase 12 | Controlled Execution | Phase 15 runs before Phase 12 checks |
| Phase 13 | Governance Design | Phase 15 addresses R4, R5, adds R7 |
| Phase 14 | Observability | Phase 15 builds on detection signals |
| Phase 15 | Enforcement | THIS DOCUMENT |

--------------------------------------------------------------------------------

## 11. Open Questions for Review

Q1. Should AICTRL-7004 (detached HEAD) be DENY or WARN by default?
    - DENY: Prevents accidental work in detached state
    - WARN: Less disruptive, accommodates git bisect workflows

Q2. Should enforcement apply to aictrl demo?
    - YES: Demo creates artifacts, should respect location
    - NO: Demo is for demonstration purposes, enforcement adds friction

Q3. Should the approved alternate location env var support multiple paths?
    - Single path: AICTRL_APPROVED_LOCATION=/path/to/alt
    - Multiple paths: AICTRL_APPROVED_LOCATIONS=/path1:/path2
    - Config file: .aictrl-locations.json with approved paths

Q4. Should enforcement record denials to a persistent log?
    - YES: Provides audit trail of blocked attempts
    - NO: Keep Phase 15 simple, defer logging to Phase 16
    - Structured JSON to stderr is sufficient for now

Q5. Should Phase 15 check for clean working tree status?
    - YES: Dirty working tree indicates unfinished work
    - NO: Working tree cleanliness is not a location concern
    - WARN-ONLY: Surface as advisory, do not block

--------------------------------------------------------------------------------

## 12. Document History

Draft 1.0 (2026-02-05):
- Initial design document
- Motivated by discovered submodule drift failure mode
- Defines 7 failure cases in threat model
- Specifies AICTRL-7xxx error code range
- Defines flag-gated rollout with warn-only default
- Establishes enforcement decision flowchart
- Maps backwards-compatibility guarantees
- Outlines test strategy (design-only)
- Defers implementation to separate PR pending approval

--------------------------------------------------------------------------------

END OF DOCUMENT
