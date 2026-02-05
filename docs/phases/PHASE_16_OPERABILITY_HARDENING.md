# Phase 16: Operability Hardening for Location Guardrails

Status: DESIGN + IMPLEMENTATION - Phase 16

Date: 2026-02-05 (UTC)

---

## 1. Goals

### 1.1 Messaging Clarity

- Consistent, predictable output format for warnings and denials
- Stable JSON keys for programmatic consumption
- Clear distinction between warn-only mode and enforcement mode
- Human-readable messages with actionable hints

### 1.2 Operability

- Self-diagnosis command for operators to inspect location state
- Quick answers to "why is this failing?" without reading source code
- No guessing required: all detection results visible

### 1.3 Determinism

- Denials only occur when violation is **proven** (not suspected)
- Unknown state = no denial (safe default)
- CI always exempt, no exceptions
- Exit code 2 only when enforcement ON and violation proven

---

## 2. Non-Goals

The following are explicitly out of scope for Phase 16:

- **No new enforcement categories**: No AICTRL-7006 or beyond
- **No baseline/tag changes**: Baseline artifacts remain untouched
- **No CI enforcement**: CI environments remain permanently exempt
- **No auto-enablement**: Default remains warn-only
- **No breaking changes**: Phase 14/15 behavior preserved

---

## 3. User Stories

### 3.1 Developer Running Locally

As a developer, I want to:
- See clear warnings if I'm in the wrong location (without being blocked)
- Run a diagnostic command to understand my current location state
- Enable enforcement optionally to validate my setup

### 3.2 Release Engineer

As a release engineer, I want to:
- Enable enforcement to ensure releases come from canonical location
- See deterministic error codes when violations occur
- Trust that unknown states won't cause false denials

### 3.3 CI System

As a CI system, I want to:
- Never be blocked by location enforcement
- Still emit warnings for observability/logging
- Have exemption apply regardless of environment variable state

---

## 4. Acceptance Criteria Checklist

All criteria must be testable:

### 4.1 Message Format

- [ ] Every warning includes: source, artifact, code, message
- [ ] Every denial includes: code, message, hint
- [ ] All message strings are ASCII-only
- [ ] JSON keys are stable across versions

### 4.2 Diagnose Command

- [ ] `python -m aictrl diagnose-location` exists and runs
- [ ] Always exits 0 (never fails, even with violations)
- [ ] Prints: cwd_realpath, canonical_path, is_submodule, origin_url,
      is_detached_head, is_symlinked, enforcement_enabled, ci_detected
- [ ] Output is ASCII-only and human-readable

### 4.3 Enforcement Behavior

- [ ] Enforcement OFF: warnings emitted, no denial, exit 0
- [ ] Enforcement ON + no violation: no denial, exit 0
- [ ] Enforcement ON + violation proven: denial, exit 2
- [ ] Enforcement ON + unknown state: no denial (safe default)
- [ ] CI detected: no denial regardless of flag

### 4.4 Backward Compatibility

- [ ] Phase 14 warning format preserved
- [ ] Phase 15 error codes unchanged (7001-7005)
- [ ] Default behavior unchanged (warn-only)

---

## 5. Message Format Contract

### 5.1 Warning Format (Phase 14 Compatible)

```json
{
  "source": "observability",
  "artifact": "location",
  "code": "AICTRL-7001",
  "message": "Non-canonical working location: /tmp/other (expected: ~/work/aictrl)"
}
```

Required keys:
- `source`: Always "observability"
- `artifact`: Always "location"
- `code`: One of AICTRL-7001 through AICTRL-7005
- `message`: Human-readable ASCII string

### 5.2 Denial Format (Phase 15 Compatible)

```json
{
  "code": "AICTRL-7001",
  "message": "Non-canonical working location detected",
  "hint": "Run from the canonical location: ~/work/aictrl",
  "actual_path": "/tmp/other",
  "expected_path": "~/work/aictrl"
}
```

Required keys:
- `code`: Error code
- `message`: Human-readable description
- `hint`: Actionable remediation

Optional keys (vary by violation type):
- `actual_path`, `expected_path`, `actual_remote`, `parent_repo`

### 5.3 Diagnose Output Format

```
=== aictrl location diagnosis ===
cwd_realpath:        /home/user/work/aictrl
canonical_path:      /home/user/work/aictrl
is_canonical:        true
is_submodule:        false
origin_url:          https://github.com/FilterProofLLC/aictrl.git
is_canonical_remote: true
is_detached_head:    false
is_symlinked:        false
enforcement_enabled: false
ci_detected:         false
status:              OK (no violations detected)
```

---

## 6. Backward Compatibility

### 6.1 Phase 14 Compatibility

When enforcement is OFF (default):
- All location checks emit warnings in Phase 14 format
- No exit code changes
- No new required fields in warning output

### 6.2 Phase 15 Compatibility

- Error codes AICTRL-7001 through 7005 unchanged
- Denial format unchanged
- Exit code 2 semantics unchanged
- CI exemption unchanged

### 6.3 No Breaking Changes

- Existing scripts parsing warning output will continue to work
- Existing error handling for exit code 2 will continue to work
- No new mandatory environment variables

---

## 7. Implementation Notes

### 7.1 Diagnose Command Location

Add to `aictrl/__main__.py` or as subcommand in CLI.

### 7.2 Testing Strategy

- Mock subprocess calls (no real git needed)
- Test message format stability with schema validation
- Test all enforcement paths with deterministic mocks

### 7.3 Documentation Updates

- Update CLI help text
- Add diagnose-location to command reference

---

## 8. Phase Boundary

Phase 16 delivers:
- Diagnose command implementation
- Message format validation tests
- Operability documentation

Phase 16 does NOT deliver:
- New enforcement categories
- Baseline changes
- CI enforcement capability
- Auto-enablement logic

---

*End of Document*
