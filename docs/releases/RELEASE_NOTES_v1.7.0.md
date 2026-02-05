# Release v1.7.0

**Date:** 2026-02-05 (UTC)

**Summary:** Phase 15 location enforcement capability with flag-gated activation.

---

## Highlights

- Location enforcement capability fully implemented (Phase 15.1, 15.2)
- Five new error codes for location-based policy violations
- Default behavior remains **warn-only** (no breaking changes)
- Enforcement available via explicit opt-in environment variable
- CI environments always exempt from enforcement
- Rollout policy documented (Phase 15.3)

---

## Behavior

**Default behavior is warn-only unless `AICTRL_ENFORCE_LOCATION=1` is set.**

| `AICTRL_ENFORCE_LOCATION` | Behavior |
|---------------------------|----------|
| unset / `0` / empty | Warn-only (Phase 14 observability) |
| `1` / `true` | Enforce (exit code 2 on violation) |

CI environments are **always exempt** from enforcement, regardless of flag state.

---

## New Error Codes

| Code | Description |
|------|-------------|
| AICTRL-7001 | Non-canonical working location |
| AICTRL-7002 | Submodule execution detected |
| AICTRL-7003 | Origin remote mismatch |
| AICTRL-7004 | Detached HEAD state |
| AICTRL-7005 | Symlinked working path |

All error codes are in the 7xxx range reserved for location enforcement (Phase 15).

---

## Docs Added

| Document | Description |
|----------|-------------|
| `docs/phases/PHASE_15_ENFORCEMENT_DESIGN.md` | Threat model, error taxonomy, decision flowchart |
| `docs/phases/PHASE_15_3_ENFORCEMENT_ROLLOUT_POLICY.md` | Activation policy and rollout guidance |

---

## Compatibility

- **Baseline artifacts:** No changes to version or tags in baseline
- **CI exemption:** Preserved; CI environments are never blocked
- **Exit codes:** Exit code 2 only when enforcement is enabled AND a violation is detected
- **Phase 14 observability:** Preserved; warnings emitted regardless of enforcement mode
- **Phase 12 invariants:** Preserved; governance model unchanged

---

## How to Enable Enforcement

To enable location enforcement, set the environment variable before running aictrl:

```
AICTRL_ENFORCE_LOCATION=1 aictrl <command>
```

**Expected behavior when violation is detected:**

- Exit code: 2
- Error message includes violation code (e.g., AICTRL-7001)
- Hint provided for remediation

**Example deny output:**

```
error: Non-canonical working location detected (AICTRL-7001)
hint: Run from the canonical location: /home/user/work/aictrl
```

---

## Contributors

- Phase 15.1: Minimal flag-gated location enforcement (PR #15)
- Phase 15.2: Additional enforcement checks (PR #16)
- Phase 15.3: Rollout policy documentation (PR #17)

---

*End of Release Notes*
