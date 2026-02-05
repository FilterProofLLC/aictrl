# Phase 17: Adoption and CI Policy Design for Location Guardrails

**Status: DESIGN ONLY - No Implementation**

**Date:** 2026-02-05 (UTC)

---

## 1. Motivation

Phase 17 addresses the gap between having location guardrails (Phases 14-16)
and having a coherent policy for when and where to enable them.

### 1.1 Discovered Failure Mode

The AIOS submodule drift incident revealed critical gaps:

1. **Non-canonical execution**: Developers ran aictrl from the AIOS submodule
   (`~/work/AIOS/tools/aictrl`) rather than the canonical clone (`~/work/aictrl`).

2. **Submodule drift**: The submodule pointer fell behind the canonical repo,
   causing version confusion and divergent behavior.

3. **Uncommitted artifacts**: Baseline artifacts were generated in the wrong
   location, never committed, and lost during context switches.

4. **Silent failure**: Without enforcement, warnings were ignored and the
   problem compounded over multiple sessions.

### 1.2 Why Policy Matters

Technical guardrails (Phases 14-16) provide detection and enforcement
mechanisms. But without a clear policy:

- Developers do not know when to enable enforcement
- CI pipelines lack consistent behavior across repos
- Release processes have no gate to prevent drift
- Operators cannot distinguish "expected warning" from "actionable violation"

Phase 17 defines the policy layer that makes guardrails actionable.

---

## 2. Non-Goals

Phase 17 explicitly does NOT include:

- **No runtime code changes**: All code remains as of Phase 16 / v1.8.0
- **No new error codes**: AICTRL-7001 through 7005 remain the complete set
- **No test changes**: Existing test suite is sufficient
- **No version or tag changes**: Next version will be Phase 18+
- **No baseline artifact changes**: Baseline remains frozen
- **No automatic enforcement enablement**: Policy is opt-in guidance only
- **No CI job implementation**: This phase designs what CI should do, not how

---

## 3. Definitions

### 3.1 Canonical Clone

A **canonical clone** is a git working directory that satisfies ALL of:

1. **Path match**: `realpath(cwd)` equals the configured canonical path
   (default: `~/work/aictrl` or `$AICTRL_CANONICAL_PATH`)

2. **Remote match**: `git remote get-url origin` resolves to the canonical
   remote URL (default: `github.com/FilterProofLLC/aictrl`)

3. **Not a submodule**: The `.git` entry is a directory, not a gitfile pointer

4. **Not symlinked**: `realpath(cwd)` equals `pwd` (no symlink indirection)

### 3.2 Approved Alternate Locations

An **approved alternate location** is a non-canonical path explicitly
attested for a specific use case. Examples:

| Use Case | Alternate Path | Attestation Method |
|----------|----------------|-------------------|
| CI runner | `/home/runner/work/...` | `CI=true` env var |
| Container build | `/app/aictrl` | `AICTRL_APPROVED_PATH` env var |
| Fork development | `~/work/my-fork` | `AICTRL_APPROVED_PATH` env var |

Approved alternates suppress enforcement denials but still emit warnings
for observability.

### 3.3 Enforcement OFF vs ON

| Mode | Trigger | Behavior |
|------|---------|----------|
| OFF (default) | `AICTRL_ENFORCE_LOCATION` unset or `0` | Warnings emitted, no denial, exit 0 |
| ON | `AICTRL_ENFORCE_LOCATION=1` | Warnings emitted, denial on proven violation, exit 2 |

**Critical invariant**: Exit code 2 occurs ONLY when:
- Enforcement is ON, AND
- A violation is proven (not suspected or unknown)

Unknown state (e.g., git command failure) never triggers denial.

### 3.4 CI Exemption Policy

**What counts as CI:**

Detection uses standard CI environment variables:
- `CI=true`
- `GITHUB_ACTIONS=true`
- `GITLAB_CI=true`
- `JENKINS_URL` set
- `TRAVIS=true`
- `CIRCLECI=true`

**Why CI is exempt (Phase 17 policy):**

1. CI paths are inherently non-canonical (runner workspaces vary)
2. CI already has artifact isolation (fresh checkout each run)
3. Breaking CI on rollout creates immediate friction with no benefit
4. CI telemetry provides visibility without blocking

**When CI becomes enforceable (future phases):**

CI enforcement requires:
1. `AICTRL_APPROVED_PATH` mechanism implemented (Phase 18+)
2. CI job explicitly opts in via `AICTRL_ENFORCE_LOCATION=1`
3. Escape hatch documented for CI breakage scenarios

---

## 4. Adoption Policy Matrix

| Environment | Default Flag | Allowed Overrides | Expected Behavior | Remediation Steps | Audit Trail |
|-------------|--------------|-------------------|-------------------|-------------------|-------------|
| **Local dev** | OFF | `AICTRL_ENFORCE_LOCATION=1` | Warn-only; developer sees warnings | Clone to canonical path; avoid submodule execution | Terminal output only |
| **CI (build)** | OFF (exempt) | None currently | Warn-only; warnings in job logs | N/A (exempt by policy) | Job logs + diagnose-location JSON artifact |
| **CI (test)** | OFF (exempt) | None currently | Warn-only; warnings in job logs | N/A (exempt by policy) | Job logs + diagnose-location JSON artifact |
| **Release pipeline** | ON (recommended) | `AICTRL_ENFORCE_LOCATION=0` to disable | Block on violation; require canonical clone | Run release from canonical clone only | Signed release artifacts + denial logs |
| **Security-sensitive** | ON (required) | None | Block on violation; no override allowed | Canonical clone mandatory | Full audit log with attestation |
| **Contributor forks** | OFF | `AICTRL_ENFORCE_LOCATION=1` optional | Warn-only; fork paths differ by design | Use `AICTRL_APPROVED_PATH` when implemented | Fork-local only |

---

## 5. CI Strategy Design

### 5.1 What CI Should Run

Every CI job that uses aictrl should include a diagnostic step:

```yaml
# Example GitHub Actions step (design only - not implemented)
- name: AICtrl Location Diagnostics
  run: |
    python -m aictrl diagnose-location --json > aictrl-location.json
    git status --porcelain > git-status.txt
    cat aictrl-location.json
```

### 5.2 What CI Should Record as Artifacts

| Artifact | Purpose | Retention |
|----------|---------|-----------|
| `aictrl-location.json` | Machine-readable location diagnosis | 30 days |
| `git-status.txt` | Working tree state at execution time | 30 days |
| Job log excerpt | Human-readable warnings | Per CI provider default |

### 5.3 Non-Blocking to Blocking Transition

**Phase A (current)**: CI runs diagnose-location, records artifacts, never fails.

**Phase B (future)**: CI fails if `enforcement_enabled: true` AND `status` contains violations,
but only in explicitly opted-in jobs.

**Phase C (future)**: Release pipeline requires enforcement ON and clean status.

**Criteria for Phase B activation:**
1. Zero false positives in 30 days of Phase A telemetry
2. Remediation documentation complete
3. Escape hatch mechanism tested

**Criteria for Phase C activation:**
1. Phase B stable for 14 days
2. All release engineers trained
3. Rollback procedure documented

---

## 6. Remediation Guidance Design

### 6.1 Violation-Specific Remediation

| Code | Violation | Remediation Steps |
|------|-----------|-------------------|
| AICTRL-7001 | Non-canonical path | 1. Clone repo to canonical location (`~/work/aictrl`)<br>2. Or set `AICTRL_APPROVED_PATH` (when implemented)<br>3. Verify: `python -m aictrl diagnose-location` shows `is_canonical: true` |
| AICTRL-7002 | Submodule execution | 1. Do NOT run aictrl from parent repo's `tools/aictrl`<br>2. Use the standalone canonical clone<br>3. If submodule use is required, set `AICTRL_APPROVED_PATH` |
| AICTRL-7003 | Origin remote mismatch | 1. Verify remote: `git remote get-url origin`<br>2. Update if wrong: `git remote set-url origin <canonical-url>`<br>3. Or explicitly approve the alternate remote |
| AICTRL-7004 | Detached HEAD | 1. Checkout a branch: `git checkout main`<br>2. If intentional (CI, tag checkout), this is informational only<br>3. Detached HEAD alone does not block unless combined with other violations |
| AICTRL-7005 | Symlinked path | 1. Access repo via real path, not symlink<br>2. Remove symlink or update workflow to use `realpath`<br>3. If symlink is intentional, set `AICTRL_APPROVED_PATH` |

### 6.2 Messaging Contract Elements

Every warning/denial message MUST include:

**Machine-readable fields (JSON):**
- `code`: Error code (e.g., "AICTRL-7001")
- `actual_value`: What was detected
- `expected_value`: What was expected (if applicable)
- `enforcement_enabled`: Boolean
- `ci_detected`: Boolean

**Human-readable text:**
- `message`: One-line description
- `hint`: Actionable remediation (one sentence)
- `docs_url`: Link to full remediation docs (when available)

Example denial output:

```
error: Non-canonical working location detected (AICTRL-7001)
  actual: /tmp/other-clone
  expected: /home/user/work/aictrl
hint: Clone the repo to the canonical location or set AICTRL_APPROVED_PATH.
docs: https://github.com/FilterProofLLC/aictrl/blob/main/docs/LOCATION_GUARDRAILS.md
```

---

## 7. Rollout Phases

### Phase A: Documentation + Optional Local Opt-In

**Scope:** This phase (Phase 17 design + Phase 18 implementation)

**Actions:**
- Publish adoption policy documentation
- Developers can opt-in via `AICTRL_ENFORCE_LOCATION=1`
- No CI changes
- No breaking changes

**Success criteria:**
- Documentation reviewed and merged
- At least 3 developers have tested enforcement locally
- Zero reports of false positives

### Phase B: Non-Blocking CI Telemetry

**Scope:** Phase 19+

**Actions:**
- Add diagnose-location step to CI jobs
- Record JSON artifacts for all runs
- Aggregate telemetry (violation frequency, false positive rate)
- CI remains non-blocking

**Success criteria:**
- 30 days of telemetry collected
- False positive rate < 1%
- Remediation docs cover all observed violations

### Phase C: Blocking in Release Pipeline

**Scope:** Phase 20+

**Actions:**
- Release pipeline enables `AICTRL_ENFORCE_LOCATION=1`
- Releases blocked if violations detected
- Escape hatch available for emergencies

**Success criteria:**
- Zero release pipeline failures due to false positives
- All releases come from canonical location
- Submodule drift incident cannot recur

### Phase D: Default-On Enforcement

**Scope:** Major version bump (v2.0.0+)

**Actions:**
- Default changes from OFF to ON
- Breaking change requires major version
- Migration guide published
- Legacy workflows have 6-month deprecation window

**Success criteria:**
- Community feedback incorporated
- No regressions in existing workflows
- Clear documentation of behavioral change

---

## 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **False positives** | Medium | High (blocks legitimate work) | Extensive testing in Phase A/B; escape hatch mechanism; `AICTRL_APPROVED_PATH` |
| **Path normalization edge cases** | Medium | Medium | Use `realpath` consistently; handle Windows paths if needed |
| **Remote URL parsing variability** | Low | Medium | Normalize all URL formats (HTTPS, SSH, git@) before comparison |
| **Monorepo/submodule workflows** | High | High | Explicit submodule policy; `AICTRL_APPROVED_PATH` for approved submodules |
| **Developer friction** | Medium | Medium | Default OFF; clear docs; opt-in only initially |
| **CI environment detection gaps** | Low | Low | Expand CI detection list as needed; explicit opt-out available |
| **Symlink detection failures** | Low | Low | `realpath` is reliable on POSIX; document Windows limitations |
| **Enforcement bypass via env var** | Medium | Low | Acceptable for Phase A-C; Phase D makes enforcement default |

---

## 9. Backward Compatibility Guarantees

### 9.1 Phase 12 Invariants Preserved

- Governance model unchanged
- Execution flow unchanged
- Baseline artifacts unchanged
- All Phase 12 commands work identically

### 9.2 Phase 14 Contracts Preserved

- Warning format: `{"source": "observability", "artifact": "location", ...}`
- All warning fields remain stable
- New fields are additive only

### 9.3 Phase 16 Contracts Preserved

- `diagnose-location` command interface unchanged
- JSON output schema stable
- Exit code 0 for diagnose-location (always)
- Exit code 2 only when enforcement ON and violation proven

### 9.4 No Breaking Changes in Phase 17

Phase 17 is design-only. No runtime behavior changes until Phase 18+.

---

## 10. Open Questions

The following must be resolved before Phase 18 implementation:

1. **AICTRL_APPROVED_PATH implementation**: How should multiple approved paths be specified? Colon-separated? JSON file?

2. **Attestation mechanism**: Should approved paths require cryptographic attestation, or is env var sufficient?

3. **Windows path handling**: How should canonical path comparison work on Windows (case sensitivity, drive letters, UNC paths)?

4. **CI job template**: Should aictrl provide an official GitHub Actions action for location diagnostics?

5. **Telemetry aggregation**: Where should CI telemetry be aggregated? Separate service? GitHub API?

6. **Escape hatch design**: What is the exact mechanism for emergency bypass in release pipeline?

7. **Fork policy refinement**: Should forks be permanently exempt, or should they have a separate canonical path config?

---

## 11. Phase Boundary

**Implementation belongs to Phase 18 or later.**

Phase 17 delivers:
- This design document
- No code changes
- No test changes
- No version changes

Phase 18+ will implement:
- `AICTRL_APPROVED_PATH` environment variable
- CI job templates
- Enhanced remediation messaging
- Telemetry collection (if decided)

---

## 12. Document History

| Date | Author | Change |
|------|--------|--------|
| 2026-02-05 | Phase 17 Design | Initial design document |

---

## 13. References

| Document | Description |
|----------|-------------|
| `PHASE_14_PART_1_OBSERVABILITY_DESIGN.md` | Observability warning format and location detection |
| `PHASE_15_ENFORCEMENT_DESIGN.md` | Flag-gated enforcement, error codes AICTRL-7001 through 7005 |
| `PHASE_15_3_ENFORCEMENT_ROLLOUT_POLICY.md` | Initial rollout policy framework |
| `PHASE_16_OPERABILITY_HARDENING.md` | diagnose-location command, message contracts, determinism |
| `RELEASE_NOTES_v1.7.0.md` | Phase 15 release details |
| `RELEASE_NOTES_v1.8.0.md` | Phase 16 release details |

---

*End of Document*
