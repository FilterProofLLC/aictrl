# Phase 18: CI Telemetry Implementation

**Status: IMPLEMENTED**

**Date:** 2026-02-05 (UTC)

---

## 1. Summary

Phase 18 adds CI telemetry for the `diagnose-location` command, making
location guardrails observable in CI without changing default behavior.

This phase implements the "Phase B: Non-Blocking CI Telemetry" rollout
stage defined in the Phase 17 design document.

---

## 2. What Was Added

### 2.1 GitHub Actions Workflow

**File:** `.github/workflows/location-telemetry.yml`

**Triggers:**
- `pull_request` - runs on all PRs
- `push` to `main` - runs on main branch pushes
- `workflow_dispatch` - manual trigger available

**Steps:**
1. Checkout repository
2. Setup Python 3.11
3. Install aictrl (editable install)
4. Show aictrl version in logs
5. Run `python -m aictrl diagnose-location --json`
6. Parse and print single-line summary
7. Upload JSON as artifact

### 2.2 Artifact Produced

**Name:** `aictrl-diagnose-location`

**Contents:** `aictrl-diagnose-location.json`

**Retention:** 30 days

**Example output:**
```json
{
  "cwd_realpath": "/home/runner/work/aictrl/aictrl",
  "canonical_path": "/home/filterprooftravis/work/aictrl",
  "is_canonical": false,
  "is_submodule": false,
  "origin_url": "https://github.com/FilterProofLLC/aictrl",
  "is_canonical_remote": true,
  "is_detached_head": false,
  "is_symlinked": false,
  "enforcement_enabled": false,
  "ci_detected": true,
  "violations": ["AICTRL-7001"],
  "status": "VIOLATIONS DETECTED: AICTRL-7001"
}
```

---

## 3. Behavior Guarantees

### 3.1 Non-Blocking

The workflow job **never fails** based on violations:
- `diagnose-location` always exits 0
- Summary parsing always exits 0
- Violations are data for observability, not gating

### 3.2 No Changes to Runtime Behavior

- Default remains warn-only (`AICTRL_ENFORCE_LOCATION` unset)
- CI exemption unchanged
- `diagnose-location` still exits 0 regardless of violations
- No new enforcement checks
- No new error codes

### 3.3 ASCII-Only

All new files are ASCII-only (verified via grep).

---

## 4. Telemetry Summary Format

The workflow prints a summary for easy log scanning:

```
=== Location Telemetry Summary ===
enforcement_enabled: False
is_canonical: False
is_submodule: False
violations: ['AICTRL-7001']
=== End Summary ===
```

This allows searching CI logs for specific patterns.

---

## 5. How to Use

### View in CI

1. Navigate to the Actions tab
2. Select a "Location Telemetry" workflow run
3. View the job logs for the summary
4. Download the `aictrl-diagnose-location` artifact for full JSON

### Manual Trigger

Use the "Run workflow" button on the Actions page to trigger manually.

---

## 6. Phase Boundary

Phase 18 implements non-blocking CI telemetry only.

**Not implemented (future phases):**
- Blocking CI based on violations (Phase 19+)
- `AICTRL_APPROVED_PATH` mechanism (Phase 19+)
- Telemetry aggregation/dashboards

---

## 7. References

| Document | Description |
|----------|-------------|
| `PHASE_16_OPERABILITY_HARDENING.md` | diagnose-location command design |
| `PHASE_17_ADOPTION_AND_CI_POLICY_DESIGN.md` | CI strategy and rollout phases |

---

*End of Document*
