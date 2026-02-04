"""Tests for bbail attest command - attestation simulation.

These tests verify that attestation is:
1. Simulation only - no real cryptographic signing
2. Deterministic - same inputs produce same outputs
3. Correctly bound to boot/invariant/evidence
4. Safe - no private keys, no network, no hardware

CRITICAL: Attestation is NOT authentication. Attestation is NOT authorization.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from aictrl.commands.attest import (
    ATTEST_CONTEXT_ERROR,
    ATTEST_IDENTITY_MISMATCH,
    ATTEST_STATEMENT_PARSE_ERROR,
    REQUIRED_NOTICES,
    calculate_sha256,
    compute_attestation_identity,
    generate_attestation_statement,
    verify_attestation_statement,
    compare_attestation_statements,
)
from aictrl.util.errors import BbailError


class TestAttestationBasics:
    """Test basic attestation functionality."""

    def test_required_notices_present(self):
        """Verify required notices are defined."""
        assert len(REQUIRED_NOTICES) >= 4

        # Check critical disclaimers
        critical_notices = [n for n in REQUIRED_NOTICES if n["severity"] == "critical"]
        assert len(critical_notices) >= 3

        # Check for NOT authentication notice
        messages = [n["message"] for n in REQUIRED_NOTICES]
        assert any("NOT authentication" in m for m in messages)
        assert any("NOT authorization" in m for m in messages)

    def test_sha256_deterministic(self):
        """SHA-256 produces same hash for same content."""
        content = b"test content"
        hash1 = calculate_sha256(content)
        hash2 = calculate_sha256(content)
        assert hash1 == hash2

    def test_sha256_format(self):
        """SHA-256 produces 64-char lowercase hex string."""
        hash_value = calculate_sha256(b"test")
        assert len(hash_value) == 64
        assert hash_value == hash_value.lower()


class TestAttestationIdentity:
    """Test attestation identity computation."""

    def test_identity_deterministic(self):
        """Same inputs produce same attestation identity."""
        boot = "a" * 64
        inv = "b" * 64
        ctx = "aios-sandbox"

        id1 = compute_attestation_identity(boot, inv, ctx)
        id2 = compute_attestation_identity(boot, inv, ctx)
        assert id1 == id2

    def test_identity_changes_with_boot(self):
        """Attestation identity changes when boot identity changes."""
        boot1 = "a" * 64
        boot2 = "c" * 64
        inv = "b" * 64
        ctx = "aios-sandbox"

        id1 = compute_attestation_identity(boot1, inv, ctx)
        id2 = compute_attestation_identity(boot2, inv, ctx)
        assert id1 != id2

    def test_identity_changes_with_invariants(self):
        """Attestation identity changes when invariant hash changes."""
        boot = "a" * 64
        inv1 = "b" * 64
        inv2 = "d" * 64
        ctx = "aios-sandbox"

        id1 = compute_attestation_identity(boot, inv1, ctx)
        id2 = compute_attestation_identity(boot, inv2, ctx)
        assert id1 != id2

    def test_identity_changes_with_context(self):
        """Attestation identity changes when context changes."""
        boot = "a" * 64
        inv = "b" * 64
        ctx1 = "aios-sandbox"
        ctx2 = "aios-dev"

        id1 = compute_attestation_identity(boot, inv, ctx1)
        id2 = compute_attestation_identity(boot, inv, ctx2)
        assert id1 != id2


class TestGenerateAttestationStatement:
    """Test attestation statement generation."""

    @pytest.fixture
    def mock_boot_and_invariants(self):
        """Mock boot measurements and invariant checks."""
        mock_boot = {
            "boot_identity_hash": "da74a7ea" + "0" * 56,
            "measurement_count": 6,
            "measurements": [
                {"id": f"M{i}", "name": f"measurement_{i}", "hash": "0" * 64, "algorithm": "SHA-256"}
                for i in range(1, 7)
            ],
        }

        mock_invariants = {
            "summary": {
                "passed": 3,
                "failed": 0,
                "skipped": 16,
                "warned": 0,
                "overall_status": "pass",
            },
            "context_checked": "aios-sandbox",
            "results_hash": "e3b0c442" + "0" * 56,
        }

        with mock.patch("aictrl.commands.attest.get_boot_measurements", return_value=mock_boot):
            with mock.patch("aictrl.commands.attest.get_invariant_results", return_value=mock_invariants):
                yield mock_boot, mock_invariants

    def test_generate_returns_valid_structure(self, mock_boot_and_invariants):
        """Verify generated statement has valid structure."""
        statement = generate_attestation_statement(context="aios-sandbox")

        assert "attestation_statement" in statement
        stmt = statement["attestation_statement"]

        # Check required fields
        assert stmt["version"] == "1.0"
        assert "statement_id" in stmt
        assert "generated_at" in stmt
        assert stmt["context"] == "aios-sandbox"
        assert "claims" in stmt
        assert "bindings" in stmt
        assert "identity" in stmt
        assert "signature_placeholder" in stmt
        assert "notices" in stmt

    def test_generate_includes_boot_claims(self, mock_boot_and_invariants):
        """Verify boot claims are included."""
        mock_boot, _ = mock_boot_and_invariants
        statement = generate_attestation_statement(context="aios-sandbox")

        boot_claims = statement["attestation_statement"]["claims"]["boot"]
        assert boot_claims["boot_identity_hash"] == mock_boot["boot_identity_hash"]
        assert boot_claims["measurement_count"] == 6
        assert len(boot_claims["measurements"]) == 6

    def test_generate_includes_invariant_claims(self, mock_boot_and_invariants):
        """Verify invariant claims are included."""
        _, mock_inv = mock_boot_and_invariants
        statement = generate_attestation_statement(context="aios-sandbox")

        inv_claims = statement["attestation_statement"]["claims"]["invariants"]
        assert inv_claims["summary"]["passed"] == mock_inv["summary"]["passed"]
        assert inv_claims["results_hash"] == mock_inv["results_hash"]

    def test_generate_includes_bindings(self, mock_boot_and_invariants):
        """Verify bindings are included."""
        statement = generate_attestation_statement(context="aios-sandbox")

        bindings = statement["attestation_statement"]["bindings"]
        assert bindings["boot_measurement_log"]["bound"] is True
        assert bindings["invariant_check"]["bound"] is True
        assert bindings["evidence_bundle"]["bound"] is False

    def test_generate_includes_identity(self, mock_boot_and_invariants):
        """Verify attestation identity is computed."""
        statement = generate_attestation_statement(context="aios-sandbox")

        identity = statement["attestation_statement"]["identity"]
        assert "attestation_id" in identity
        assert identity["algorithm"] == "SHA-256"
        assert "components" in identity

    def test_generate_signature_not_implemented(self, mock_boot_and_invariants):
        """Verify signature is not implemented (simulation only)."""
        statement = generate_attestation_statement(context="aios-sandbox")

        sig = statement["attestation_statement"]["signature_placeholder"]
        assert sig["signed"] is False
        assert sig["algorithm"] == "none"
        assert sig["value"] is None

    def test_generate_includes_required_notices(self, mock_boot_and_invariants):
        """Verify required notices are included."""
        statement = generate_attestation_statement(context="aios-sandbox")

        notices = statement["attestation_statement"]["notices"]
        messages = [n["message"] for n in notices]

        # Check critical disclaimers
        assert any("SIMULATION ONLY" in m for m in messages)
        assert any("NOT authentication" in m for m in messages)
        assert any("NOT authorization" in m for m in messages)

    def test_generate_rejects_non_sandbox(self, mock_boot_and_invariants):
        """Verify non-sandbox context is rejected."""
        with pytest.raises(BbailError) as exc_info:
            generate_attestation_statement(context="aios-base")

        assert exc_info.value.code == ATTEST_CONTEXT_ERROR

    def test_generate_deterministic(self, mock_boot_and_invariants):
        """Verify same inputs produce same identity."""
        stmt1 = generate_attestation_statement(context="aios-sandbox")
        stmt2 = generate_attestation_statement(context="aios-sandbox")

        # Identity should be deterministic
        assert (
            stmt1["attestation_statement"]["identity"]["attestation_id"]
            == stmt2["attestation_statement"]["identity"]["attestation_id"]
        )


class TestVerifyAttestationStatement:
    """Test attestation statement verification."""

    @pytest.fixture
    def valid_statement(self, tmp_path):
        """Create a valid statement file."""
        statement = {
            "attestation_statement": {
                "version": "1.0",
                "statement_id": "test-uuid",
                "generated_at": "2026-01-24T12:00:00+00:00",
                "context": "aios-sandbox",
                "claims": {
                    "boot": {
                        "boot_identity_hash": "da74a7ea" + "0" * 56,
                        "measurement_count": 6,
                        "measurements": [],
                    },
                    "invariants": {
                        "summary": {"passed": 3, "failed": 0, "skipped": 16, "warned": 0, "overall_status": "pass"},
                        "context_checked": "aios-sandbox",
                        "results_hash": "e3b0c442" + "0" * 56,
                    },
                    "system": {"hostname": "test", "bbail_version": "0.1.0", "bbail_commit": "abc123"},
                },
                "bindings": {
                    "boot_measurement_log": {"bound": True, "source": "bbail boot measure", "combined_hash": "da74a7ea" + "0" * 56},
                    "invariant_check": {"bound": True, "source": "bbail doctor", "results_hash": "e3b0c442" + "0" * 56},
                    "evidence_bundle": {"bound": False, "bundle_id": None, "manifest_hash": None},
                },
                "identity": {
                    "attestation_id": None,  # Will be computed
                    "algorithm": "SHA-256",
                    "derivation": "boot_identity || invariant_hash || context",
                    "components": {
                        "boot_identity": "da74a7ea" + "0" * 56,
                        "invariant_hash": "e3b0c442" + "0" * 56,
                        "context": "aios-sandbox",
                    },
                },
                "signature_placeholder": {
                    "signed": False,
                    "algorithm": "none",
                    "value": None,
                    "signer": None,
                    "note": "Signature not implemented",
                },
                "notices": REQUIRED_NOTICES,
            }
        }

        # Compute correct identity
        identity = compute_attestation_identity(
            "da74a7ea" + "0" * 56,
            "e3b0c442" + "0" * 56,
            "aios-sandbox",
        )
        statement["attestation_statement"]["identity"]["attestation_id"] = identity

        path = tmp_path / "statement.json"
        with open(path, "w") as f:
            json.dump(statement, f)

        return path, statement

    def test_verify_valid_statement(self, valid_statement):
        """Verify valid statement passes structural verification."""
        path, _ = valid_statement

        # Mock to return matching values
        with mock.patch("aictrl.commands.attest.get_boot_measurements") as mock_boot:
            with mock.patch("aictrl.commands.attest.get_invariant_results") as mock_inv:
                mock_boot.return_value = {"boot_identity_hash": "da74a7ea" + "0" * 56}
                mock_inv.return_value = {"results_hash": "e3b0c442" + "0" * 56}

                result = verify_attestation_statement(str(path))

                assert result["identity_valid"] is True
                assert result["trust_level"] == "VERIFIED"

    def test_verify_detects_identity_mismatch(self, valid_statement, tmp_path):
        """Verify detection of identity mismatch."""
        _, statement = valid_statement

        # Corrupt the identity
        statement["attestation_statement"]["identity"]["attestation_id"] = "wrong" * 16

        path = tmp_path / "corrupted.json"
        with open(path, "w") as f:
            json.dump(statement, f)

        with pytest.raises(BbailError) as exc_info:
            verify_attestation_statement(str(path))

        assert exc_info.value.code == ATTEST_IDENTITY_MISMATCH

    def test_verify_file_not_found(self, tmp_path):
        """Verify error on missing file."""
        with pytest.raises(BbailError) as exc_info:
            verify_attestation_statement(str(tmp_path / "nonexistent.json"))

        assert exc_info.value.code == ATTEST_STATEMENT_PARSE_ERROR

    def test_verify_invalid_json(self, tmp_path):
        """Verify error on invalid JSON."""
        path = tmp_path / "invalid.json"
        path.write_text("not valid json {{{")

        with pytest.raises(BbailError) as exc_info:
            verify_attestation_statement(str(path))

        assert exc_info.value.code == ATTEST_STATEMENT_PARSE_ERROR

    def test_verify_reports_boot_mismatch(self, valid_statement):
        """Verify boot mismatch is reported."""
        path, _ = valid_statement

        # Mock to return different boot identity
        with mock.patch("aictrl.commands.attest.get_boot_measurements") as mock_boot:
            with mock.patch("aictrl.commands.attest.get_invariant_results") as mock_inv:
                mock_boot.return_value = {"boot_identity_hash": "different" + "0" * 55}
                mock_inv.return_value = {"results_hash": "e3b0c442" + "0" * 56}

                result = verify_attestation_statement(str(path))

                assert result["boot_claims_valid"] is False
                assert result["trust_level"] in ["PARTIAL", "STALE"]
                assert len(result["discrepancies"]) > 0


class TestCompareAttestationStatements:
    """Test attestation statement comparison."""

    @pytest.fixture
    def two_statements(self, tmp_path):
        """Create two statement files."""
        base_statement = {
            "attestation_statement": {
                "statement_id": "stmt1",
                "generated_at": "2026-01-24T12:00:00+00:00",
                "claims": {
                    "boot": {"boot_identity_hash": "a" * 64},
                    "invariants": {"results_hash": "b" * 64},
                },
                "identity": {"attestation_id": "c" * 64},
            }
        }

        path1 = tmp_path / "stmt1.json"
        with open(path1, "w") as f:
            json.dump(base_statement, f)

        # Create identical second statement
        base_statement["attestation_statement"]["statement_id"] = "stmt2"
        path2 = tmp_path / "stmt2.json"
        with open(path2, "w") as f:
            json.dump(base_statement, f)

        return path1, path2

    def test_compare_identical_statements(self, two_statements):
        """Verify identical statements are detected."""
        path1, path2 = two_statements
        result = compare_attestation_statements(str(path1), str(path2))

        assert result["identical"] is True
        assert result["difference_count"] == 0

    def test_compare_different_boot(self, two_statements, tmp_path):
        """Verify different boot identities are detected."""
        path1, _ = two_statements

        # Create different second statement
        statement2 = {
            "attestation_statement": {
                "statement_id": "stmt2",
                "generated_at": "2026-01-24T13:00:00+00:00",
                "claims": {
                    "boot": {"boot_identity_hash": "d" * 64},  # Different
                    "invariants": {"results_hash": "b" * 64},
                },
                "identity": {"attestation_id": "e" * 64},
            }
        }
        path2 = tmp_path / "stmt2_diff.json"
        with open(path2, "w") as f:
            json.dump(statement2, f)

        result = compare_attestation_statements(str(path1), str(path2))

        assert result["identical"] is False
        assert result["difference_count"] > 0
        assert any(d["field"] == "boot_identity" for d in result["differences"])


class TestNoPrivilegedOperations:
    """Test that attestation doesn't use privileged operations."""

    def test_no_private_key_generation(self):
        """Verify no private key generation."""
        from aictrl.commands import attest

        source = open(attest.__file__).read()
        dangerous = [
            "generate_private_key",
            "RSA.generate",
            "Ed25519PrivateKey",
            "secrets.token",
            "cryptography.hazmat",
        ]
        for term in dangerous:
            assert term not in source, f"Dangerous operation '{term}' found"

    def test_no_network_calls(self):
        """Verify no network calls."""
        from aictrl.commands import attest

        source = open(attest.__file__).read()
        network_ops = [
            "requests.",
            "urllib",
            "http.client",
            "socket.connect",
            "socket.send",
        ]
        for op in network_ops:
            assert op not in source, f"Network operation '{op}' found"

    def test_no_hardware_access(self):
        """Verify no hardware access."""
        from aictrl.commands import attest

        source = open(attest.__file__).read()
        # Note: "TPM" and "HSM" appear in comments explaining what NOT to do
        # We check for actual hardware access patterns, not documentation
        hardware_ops = [
            "/dev/tpm",
            "tpm2_",
            "pkcs11",
            "ctypes.CDLL",
        ]
        for op in hardware_ops:
            assert op not in source, f"Hardware operation '{op}' found"

    def test_no_sudo_usage(self):
        """Verify no sudo is used."""
        from aictrl.commands import attest

        source = open(attest.__file__).read()
        assert "sudo" not in source, "sudo found in attest.py"


class TestCLIIntegration:
    """Test CLI integration for attest commands."""

    @pytest.fixture
    def mock_generation(self):
        """Mock attestation generation."""
        with mock.patch("aictrl.commands.attest.get_boot_measurements") as mock_boot:
            with mock.patch("aictrl.commands.attest.get_invariant_results") as mock_inv:
                mock_boot.return_value = {
                    "boot_identity_hash": "a" * 64,
                    "measurement_count": 6,
                    "measurements": [
                        {"id": f"M{i}", "name": f"m{i}", "hash": "0" * 64, "algorithm": "SHA-256"}
                        for i in range(1, 7)
                    ],
                }
                mock_inv.return_value = {
                    "summary": {"passed": 3, "failed": 0, "skipped": 16, "warned": 0, "overall_status": "pass"},
                    "context_checked": "aios-sandbox",
                    "results_hash": "b" * 64,
                }
                yield

    def test_attest_generate_cli(self, mock_generation, tmp_path, capsys):
        """Test attest generate via CLI."""
        from aictrl.cli import main

        out_file = tmp_path / "attestation.json"
        result = main(["attest", "generate", "--context", "aios-sandbox", "--out", str(out_file)])

        assert result == 0
        assert out_file.exists()

        # Verify output
        with open(out_file) as f:
            statement = json.load(f)
        assert "attestation_statement" in statement

    def test_attest_verify_cli(self, mock_generation, tmp_path):
        """Test attest verify via CLI."""
        from aictrl.cli import main

        # Generate statement first
        out_file = tmp_path / "attestation.json"
        main(["attest", "generate", "--context", "aios-sandbox", "--out", str(out_file)])

        # Verify it
        result = main(["attest", "verify", "--statement", str(out_file)])
        assert result == 0


class TestAttestationDeterminism:
    """Test that attestation is deterministic."""

    @pytest.fixture
    def deterministic_mocks(self):
        """Provide deterministic mocks."""
        boot = {
            "boot_identity_hash": "fixed_boot_hash_" + "0" * 48,
            "measurement_count": 6,
            "measurements": [
                {"id": f"M{i}", "name": f"m{i}", "hash": f"m{i}_hash_" + "0" * 54, "algorithm": "SHA-256"}
                for i in range(1, 7)
            ],
        }
        inv = {
            "summary": {"passed": 3, "failed": 0, "skipped": 16, "warned": 0, "overall_status": "pass"},
            "context_checked": "aios-sandbox",
            "results_hash": "fixed_inv_hash_" + "0" * 50,
        }

        with mock.patch("aictrl.commands.attest.get_boot_measurements", return_value=boot):
            with mock.patch("aictrl.commands.attest.get_invariant_results", return_value=inv):
                yield

    def test_identity_is_deterministic(self, deterministic_mocks):
        """Verify attestation identity is deterministic."""
        stmt1 = generate_attestation_statement(context="aios-sandbox")
        stmt2 = generate_attestation_statement(context="aios-sandbox")

        id1 = stmt1["attestation_statement"]["identity"]["attestation_id"]
        id2 = stmt2["attestation_statement"]["identity"]["attestation_id"]

        assert id1 == id2

    def test_claims_are_deterministic(self, deterministic_mocks):
        """Verify claims are deterministic."""
        stmt1 = generate_attestation_statement(context="aios-sandbox")
        stmt2 = generate_attestation_statement(context="aios-sandbox")

        claims1 = stmt1["attestation_statement"]["claims"]
        claims2 = stmt2["attestation_statement"]["claims"]

        assert claims1["boot"] == claims2["boot"]
        assert claims1["invariants"] == claims2["invariants"]

    def test_bindings_are_deterministic(self, deterministic_mocks):
        """Verify bindings are deterministic."""
        stmt1 = generate_attestation_statement(context="aios-sandbox")
        stmt2 = generate_attestation_statement(context="aios-sandbox")

        bindings1 = stmt1["attestation_statement"]["bindings"]
        bindings2 = stmt2["attestation_statement"]["bindings"]

        assert bindings1 == bindings2
