# Release v1.9.0

**Date:** 2026-02-05 (UTC)

**Summary:** Phase 18 CI telemetry for location guardrails.

---

## Highlights

- GitHub Actions workflow for location diagnostics
- Automatic artifact upload of diagnose-location JSON
- Non-blocking telemetry for observability

**No enforcement changes. Observability only.**

---

## New Functionality

### CI Telemetry Workflow

A new GitHub Actions workflow runs automatically on:
- Pull requests
- Push to main
- Manual dispatch

**Workflow steps:**
1. Checkout and setup Python 3.11
2. Install aictrl
3. Run `python -m aictrl diagnose-location --json`
4. Upload JSON as artifact

**Artifact:** `aictrl-diagnose-location` (30-day retention)

### Non-Blocking Design

The workflow never fails based on violations:
- `diagnose-location` always exits 0
- Violations are data for observability, not gating
- CI can safely run without blocking PRs

---

## Behavior Guarantees

| Guarantee | Status |
|-----------|--------|
| Default remains warn-only | Unchanged |
| `diagnose-location` exits 0 | Unchanged |
| CI exemption | Unchanged |
| Enforcement logic | No changes |
| Error codes | No changes |

---

## Files Added

| File | Description |
|------|-------------|
| `.github/workflows/location-telemetry.yml` | CI workflow |
| `docs/phases/PHASE_18_CI_TELEMETRY_IMPLEMENTATION.md` | Implementation doc |

---

## Compatibility

- All Phase 12-17 invariants preserved
- No breaking changes
- No new dependencies

---

## Upgrade Notes

**No action required.** The CI workflow runs automatically.

To view telemetry:
1. Navigate to Actions tab
2. Select "Location Telemetry" workflow
3. Download the `aictrl-diagnose-location` artifact

---

## Contributors

- Phase 18: CI telemetry (PR #20)

---

*End of Release Notes*
