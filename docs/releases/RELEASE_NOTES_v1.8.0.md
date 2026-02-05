# Release v1.8.0

**Date:** 2026-02-05 (UTC)

**Summary:** Phase 16 operability hardening for location guardrails.

---

## Highlights

- New `diagnose-location` command for self-diagnosis
- Stable message format contracts for programmatic consumption
- Determinism guarantees: deny only when violation is proven
- Unknown state = no denial (safe default)

---

## New Functionality

### diagnose-location Command

A new command for operators to inspect location state without reading source code.

**Text output (default):**

```
python -m aictrl diagnose-location
```

**JSON output:**

```
python -m aictrl diagnose-location --json
```

**Fields reported:**

| Field | Description |
|-------|-------------|
| cwd_realpath | Current working directory (resolved) |
| canonical_path | Expected canonical path |
| is_canonical | Whether cwd matches canonical |
| is_submodule | Whether running from submodule |
| origin_url | Git origin remote URL |
| is_canonical_remote | Whether origin matches expected |
| is_detached_head | Whether HEAD is detached |
| is_symlinked | Whether path contains symlinks |
| enforcement_enabled | AICTRL_ENFORCE_LOCATION flag state |
| ci_detected | Whether CI environment detected |
| status | Summary status (OK or violation codes) |

The command always exits 0, even when violations are detected.

### Stable Message Contracts

**Warning format (Phase 14 compatible):**

```json
{
  "source": "observability",
  "artifact": "location",
  "code": "AICTRL-7001",
  "message": "Non-canonical working location: /tmp/other (expected: ~/work/aictrl)"
}
```

**Denial format (Phase 15 compatible):**

```json
{
  "code": "AICTRL-7001",
  "message": "Non-canonical working location detected",
  "hint": "Run from the canonical location: ~/work/aictrl"
}
```

All message strings are ASCII-only. JSON keys are stable across versions.

---

## Behavior Guarantees

| Condition | Result |
|-----------|--------|
| Enforcement OFF (default) | Warnings emitted, no denial, exit 0 |
| Enforcement ON + no violation | No denial, exit 0 |
| Enforcement ON + violation proven | Denial, exit 2 |
| Enforcement ON + unknown state | No denial (safe default) |
| CI detected | No denial regardless of flag |

**Key invariant:** Denial only occurs when a violation is **proven**, never on unknown or indeterminate state.

---

## Docs Added

| Document | Description |
|----------|-------------|
| `docs/phases/PHASE_16_OPERABILITY_HARDENING.md` | Design document for operability improvements |

---

## Compatibility

- **Default behavior:** Unchanged (warn-only)
- **CI exemption:** Preserved; CI environments are never blocked
- **Phase 14 warnings:** Format preserved
- **Phase 15 error codes:** AICTRL-7001 through 7005 unchanged
- **Exit codes:** Exit code 2 only when enforcement ON and violation proven
- **Baseline artifacts:** No changes

---

## Upgrade Notes

**No action required** unless opting into enforcement.

To enable enforcement, set the environment variable:

```
AICTRL_ENFORCE_LOCATION=1 aictrl <command>
```

The new `diagnose-location` command is available immediately for troubleshooting.

---

## Contributors

- Phase 16: Operability hardening (PR #18)

---

*End of Release Notes*
