# AICtrl Baseline Test Framework

## Overview

This directory contains the AICtrl 1.0.x Baseline Test framework. The baseline defines a canonical set of CLI tests that verify governance and safety guarantees, not functional execution.

**What the baseline IS:**
- A compliance artifact for audits
- Verification of invariants and policy enforcement
- Deterministic tests with mapped specification references
- Evidence that AI cannot execute or cross boundaries

**What the baseline IS NOT:**
- Functional or integration tests
- Tests requiring a running sandbox
- A replacement for unit tests

## Running the Baseline

From the repository root:

```bash
python baseline/run_baseline.py
```

Or using the Python module:

```bash
python -m baseline.run_baseline
```

### Command-Line Options

```
python baseline/run_baseline.py [--emit-json] [--emit-coverage] [--emit-digest]
python baseline/run_baseline.py --verify <artifact_dir>

Options:
  --emit-json      Also emit a JSON attestation artifact
  --emit-coverage  Also emit a spec coverage index
  --emit-digest    Also emit a cryptographic digest file for verification
  --verify <dir>   Verify existing artifacts (read-only, no test execution)
```

### Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- AICtrl 1.0.2+ installed or available as a module

### Exit Codes

- `0` - All tests passed (or failed as expected), or verification succeeded
- `1` - One or more unexpected test failures, or verification failed

## Output Artifacts

### ASCII Report (Default)

The primary human-readable report:

```
baseline/results/aictrl_baseline_<timestamp>.txt
```

Contains:
- Baseline name and version
- UTC timestamp
- Host metadata (Python version, platform, AICtrl version)
- Summary counts (pass/fail)
- Per-test details with spec mappings

### JSON Attestation (--emit-json)

Machine-readable attestation artifact:

```
baseline/results/aictrl_baseline_<timestamp>.json
```

Contains:
- Schema version (currently 1.1) and attestation type
- Baseline and AICtrl version information
- Execution context (local, CI, etc.)
- Provenance metadata (git commit, branch, repository URL, CI run ID)
- Structured test results with spec mappings
- Summary statistics

The JSON format is designed for external consumption and future attestation workflows.

### Spec Coverage Index (--emit-coverage)

Specification coverage analysis:

```
baseline/results/aictrl_spec_coverage_<timestamp>.txt
```

Contains:
- NIST AI RMF control coverage (FULL/PARTIAL/NONE)
- Internal invariant coverage
- Federal policy coverage
- Gap visibility for compliance planning

### Cryptographic Digest (--emit-digest)

Integrity verification file:

```
baseline/results/aictrl-baseline.digest.txt
```

Contains:
- SHA-256 hashes of all generated artifacts
- Git commit SHA at time of generation
- Baseline version and timestamp

The digest enables offline verification of artifact integrity without re-executing tests. When `--emit-digest` is used, stable copies of all artifacts are also created:
- `aictrl-baseline-report.txt`
- `aictrl-baseline-attestation.json` (if `--emit-json`)
- `aictrl-spec-coverage.txt` (if `--emit-coverage`)

### Artifact Verification (--verify)

Verify existing artifacts without executing tests:

```bash
python baseline/run_baseline.py --verify /path/to/artifacts
```

This read-only mode:
- Loads the digest file from the specified directory
- Computes SHA-256 hashes of existing artifacts
- Reports VERIFIED, FAILED, or MISSING for each file
- Returns exit code 0 if all files verify, 1 otherwise

Results files are not committed to the repository (see `.gitkeep`).

## Test Definitions

Tests are defined in `baseline_tests.yaml` with the following structure:

```yaml
tests:
  - id: "BL-001"
    title: "Version flag returns valid output"
    command: ["python", "-m", "aictrl", "--version"]
    expect:
      exit_code: 0
      stdout_contains:
        - "aictrl"
    spec:
      internal: "CLI-SURFACE-001"
      nist: "ID.AM-2"
      federal: "EO-14110-4.1"
    notes: "Description of what this test verifies."
```

### Test Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique test identifier (e.g., `BL-001`) |
| `title` | Yes | Human-readable test description |
| `command` | Yes | Command as argv list |
| `expect` | Yes | Expected outcomes (see below) |
| `spec` | Yes | Specification mappings |
| `notes` | No | Additional context |
| `env` | No | Environment variable overrides |
| `expected_failure` | No | If `true`, failure is expected by design |

### Expectation Fields

| Field | Description |
|-------|-------------|
| `exit_code` | Expected exit code (exact match) |
| `exit_code_in` | List of acceptable exit codes |
| `stdout_contains` | Strings that must appear in stdout |
| `stderr_contains` | Strings that must appear in stderr |
| `ascii_only` | If `true`, output must be ASCII-only |

### Specification Mapping

Each test maps to:
- `internal` - Internal invariant or specification reference (e.g., `INV-004`)
- `nist` - NIST AI RMF control (e.g., `AC-3`)
- `federal` - Federal/executive policy reference (e.g., `EO-14110-4.5`)

## Adding a New Test

1. Open `baseline_tests.yaml`
2. Add a new test entry under the `tests:` section
3. Assign a unique `id` following the pattern `BL-XXX`
4. Define the command and expectations
5. Map to appropriate specifications
6. Run the baseline to verify

Example:

```yaml
  - id: "BL-200"
    title: "New invariant verification"
    command: ["python", "-m", "aictrl", "doctor", "--check", "INV-099"]
    expect:
      exit_code: 0
      stdout_contains:
        - '"status"'
    spec:
      internal: "INV-099"
      nist: "CA-7"
      federal: "EO-14110-4.3"
    notes: "Verifies the new invariant is checked by doctor."
```

## Expected Failures

Some tests are designed to fail. These verify that the CLI correctly rejects invalid input or enforces safety guards. Tests marked with `expected_failure: true` are counted separately and do not cause the baseline to fail.

Examples:
- `BL-070`: Invalid subcommand is rejected (exit code 2)
- `BL-080`: Host safety violation without acknowledgement flag

## Test Categories

| Range | Category |
|-------|----------|
| BL-001 - BL-009 | CLI surface introspection |
| BL-010 - BL-019 | Authorization policy (deny-by-default) |
| BL-020 - BL-029 | Authorization enforcement points |
| BL-030 - BL-039 | Adapter inspection (AI prohibition) |
| BL-040 - BL-049 | Boundary inspection (AI cannot cross) |
| BL-050 - BL-059 | Execution readiness |
| BL-060 - BL-069 | Safe failure modes |
| BL-070 - BL-079 | Invalid input rejection |
| BL-080 - BL-089 | Environment override tests |
| BL-090 - BL-099 | ASCII output compliance |
| BL-100 - BL-109 | Evidence and audit trail |
| BL-110 - BL-119 | Determinism verification |

## Extending for Future Releases

When updating for new AICtrl versions:

1. Update `target_version` in `baseline_tests.yaml`
2. Add tests for new commands or invariants
3. Update existing tests if behavior changes are intentional
4. Document breaking changes in test notes
5. Maintain backward compatibility where possible

The baseline serves as a contract: if tests pass on a new version, the governance guarantees remain intact.
