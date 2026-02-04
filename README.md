# AICtrl

AICtrl - Portable AI Control Plane CLI tool.

## Overview

`aictrl` is the command-line interface for the AICtrl control plane. This tool provides:

- System status collection
- Health diagnostics (doctor)
- Support bundle generation
- Evidence bundle management
- Security invariant checks
- Authorization policy evaluation
- Baseline test framework for compliance verification

**Note:** AICtrl is a portable control plane, NOT an operating system. It runs on top of existing OSes.

## Requirements

- Python 3.10 or higher
- PyYAML (for baseline runner)
- No additional dependencies for core CLI functionality

## Installation

### Via pip (editable mode)

```bash
pip install -e .
aictrl --help
```

### Via pipx

```bash
pipx install .
aictrl --help
```

## Baseline Test Framework

AICtrl includes a compliance baseline test framework that produces auditable artifacts.

### Running Baseline Tests

```bash
# Run baseline with all artifacts
python baseline/run_baseline.py --emit-json --emit-coverage --emit-digest

# Verify existing artifacts
python baseline/run_baseline.py --verify baseline/results
```

### Baseline Artifacts

| Artifact | Description |
|----------|-------------|
| `aictrl-baseline-report.txt` | ASCII test report |
| `aictrl-baseline-attestation.json` | JSON attestation (schema v1.1) |
| `aictrl-spec-coverage.txt` | NIST/Federal spec coverage index |
| `aictrl-baseline.digest.txt` | Cryptographic digest for verification |
| `aictrl-baseline-manifest.json` | Baseline metadata |

### Expected Failures

Some tests are intentionally expected to fail (e.g., BL-080 tests host safety violation detection). These are documented in `baseline/baseline_manifest.json` under `expected_fail_test_ids`.

## CLI Commands

### `aictrl version`

Show version information with build watermarking.

```bash
aictrl version --pretty
```

### `aictrl status`

Collect and display system status information.

```bash
aictrl status --pretty
```

### `aictrl doctor`

Run system health checks.

```bash
aictrl doctor --pretty
```

Exit codes:
- 0: All checks passed
- 1: One or more checks failed

### `aictrl authz`

Evaluate authorization policy.

```bash
aictrl authz check --subject ai --action write --resource /etc/passwd
```

### `aictrl support-bundle create`

Create a diagnostic support bundle.

```bash
aictrl support-bundle create --out /tmp
```

### `aictrl evidence export`

Export evidence bundle for audit support.

```bash
aictrl evidence export --out /tmp/evidence
```

## Running Tests

```bash
# Install test dependencies
pip install pytest jsonschema

# Run all tests
python -m pytest

# Run with verbose output
python -m pytest -v
```

## Error Codes

Error codes use the `AICTRL-xxxx` format:

- `AICTRL-0xxx`: General errors
- `AICTRL-1xxx`: System errors
- `AICTRL-2xxx`: GPU errors
- `AICTRL-3xxx`: Network errors
- `AICTRL-4xxx`: AI/Container errors
- `AICTRL-5xxx`: AI interface errors

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Failure (recoverable) |
| 2 | Usage error (invalid arguments) |

## License

Proprietary - FilterProof LLC
