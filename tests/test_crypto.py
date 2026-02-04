"""Tests for crypto command module.

CRITICAL: These tests verify that the crypto module does NOT perform
any cryptographic operations. Phase 8 is DESIGN ONLY.

The crypto module MUST:
- Report configuration state only
- NOT import crypto libraries
- NOT generate keys
- NOT sign, encrypt, or hash
- Be deterministic in structure
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

# Add bbail package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.crypto import (
    STATUS_NOT_CONFIGURED,
    STATUS_CONFIGURED,
    STATUS_DEGRADED,
    PQ_MONITORING,
    PQ_PREPARING,
    PQ_HYBRID,
    PQ_MIGRATED,
    generate_timestamp,
    get_crypto_status,
    get_crypto_readiness,
    get_crypto_algorithms,
)


class TestCryptoStatusConstants:
    """Test crypto status constants."""

    def test_status_constants_defined(self):
        """Verify status constants are defined."""
        assert STATUS_NOT_CONFIGURED == "not_configured"
        assert STATUS_CONFIGURED == "configured"
        assert STATUS_DEGRADED == "degraded"

    def test_pq_posture_constants_defined(self):
        """Verify post-quantum posture constants are defined."""
        assert PQ_MONITORING == "monitoring"
        assert PQ_PREPARING == "preparing"
        assert PQ_HYBRID == "hybrid"
        assert PQ_MIGRATED == "migrated"


class TestGenerateTimestamp:
    """Test timestamp generation."""

    def test_timestamp_format(self):
        """Verify timestamp is ISO 8601 format."""
        ts = generate_timestamp()
        # Should match ISO 8601 with timezone
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts)

    def test_timestamp_has_timezone(self):
        """Verify timestamp includes timezone info."""
        ts = generate_timestamp()
        # Should contain timezone indicator (UTC offset or Z)
        assert "+" in ts or "Z" in ts


class TestGetCryptoStatus:
    """Test get_crypto_status function."""

    def test_returns_dict(self):
        """Verify function returns a dictionary."""
        result = get_crypto_status()
        assert isinstance(result, dict)

    def test_status_is_not_configured(self):
        """Verify status is not_configured (Phase 8)."""
        result = get_crypto_status()
        assert result["status"] == STATUS_NOT_CONFIGURED

    def test_has_phase_indicator(self):
        """Verify result indicates Phase 8."""
        result = get_crypto_status()
        assert "Phase 8" in result["phase"]
        assert "Design Only" in result["phase"]

    def test_has_warning_about_no_implementation(self):
        """Verify result warns that crypto is not implemented."""
        result = get_crypto_status()
        assert "NOT IMPLEMENTED" in result["warning"]

    def test_has_configuration_section(self):
        """Verify result has configuration section."""
        result = get_crypto_status()
        assert "configuration" in result
        config = result["configuration"]
        assert "signing" in config
        assert "verification" in config
        assert "encryption" in config
        assert "hashing" in config

    def test_signing_not_enabled(self):
        """Verify signing is not enabled (Phase 8)."""
        result = get_crypto_status()
        assert result["configuration"]["signing"]["enabled"] is False

    def test_verification_not_enabled(self):
        """Verify verification is not enabled (Phase 8)."""
        result = get_crypto_status()
        assert result["configuration"]["verification"]["enabled"] is False

    def test_encryption_not_enabled(self):
        """Verify encryption is not enabled (Phase 8)."""
        result = get_crypto_status()
        assert result["configuration"]["encryption"]["enabled"] is False

    def test_hashing_enabled_for_integrity(self):
        """Verify hashing is enabled for existing integrity checks."""
        result = get_crypto_status()
        hashing = result["configuration"]["hashing"]
        assert hashing["enabled"] is True
        assert hashing["algorithm"] == "SHA-256"

    def test_has_keys_section(self):
        """Verify result has keys section."""
        result = get_crypto_status()
        assert "keys" in result
        keys = result["keys"]
        assert "attestation" in keys
        assert "artifact_signing" in keys
        assert "transport" in keys

    def test_keys_not_provisioned(self):
        """Verify all keys are not_provisioned (Phase 8)."""
        result = get_crypto_status()
        for key_type in result["keys"].values():
            assert key_type["status"] == "not_provisioned"

    def test_has_hardware_section(self):
        """Verify result has hardware section."""
        result = get_crypto_status()
        assert "hardware" in result
        assert result["hardware"]["tpm_available"] is False
        assert result["hardware"]["hsm_available"] is False

    def test_has_notices(self):
        """Verify result has notices about Phase 8."""
        result = get_crypto_status()
        assert "notices" in result
        assert len(result["notices"]) > 0


class TestGetCryptoReadiness:
    """Test get_crypto_readiness function."""

    def test_returns_dict(self):
        """Verify function returns a dictionary."""
        result = get_crypto_readiness()
        assert isinstance(result, dict)

    def test_readiness_level_is_design_complete(self):
        """Verify readiness level is design_complete (Phase 8)."""
        result = get_crypto_readiness()
        assert result["readiness_level"] == "design_complete"

    def test_has_phase_indicator(self):
        """Verify result indicates Phase 8."""
        result = get_crypto_readiness()
        assert "Phase 8" in result["phase"]

    def test_has_assessment_section(self):
        """Verify result has assessment section."""
        result = get_crypto_readiness()
        assert "assessment" in result
        assessment = result["assessment"]
        assert "architecture" in assessment
        assert "key_management" in assessment
        assert "failure_handling" in assessment
        assert "implementation" in assessment

    def test_architecture_documented(self):
        """Verify architecture is marked as documented."""
        result = get_crypto_readiness()
        arch = result["assessment"]["architecture"]
        assert arch["status"] == "documented"
        assert "CRYPTO_ARCHITECTURE.md" in arch["document"]

    def test_key_management_policy_defined(self):
        """Verify key management policy is defined."""
        result = get_crypto_readiness()
        km = result["assessment"]["key_management"]
        assert km["status"] == "policy_defined"
        assert "KEY_MANAGEMENT_POLICY.md" in km["document"]

    def test_failure_model_defined(self):
        """Verify failure model is defined."""
        result = get_crypto_readiness()
        fm = result["assessment"]["failure_handling"]
        assert fm["status"] == "model_defined"
        assert "CRYPTO_FAILURE_MODEL.md" in fm["document"]

    def test_implementation_not_started(self):
        """Verify implementation is not started (Phase 8)."""
        result = get_crypto_readiness()
        impl = result["assessment"]["implementation"]
        assert impl["status"] == "not_started"
        assert "Phase 9" in impl["reason"]

    def test_has_post_quantum_section(self):
        """Verify result has post-quantum section."""
        result = get_crypto_readiness()
        assert "post_quantum" in result
        pq = result["post_quantum"]
        assert pq["posture"] == PQ_MONITORING

    def test_has_compliance_readiness(self):
        """Verify result has compliance readiness section."""
        result = get_crypto_readiness()
        assert "compliance_readiness" in result
        cr = result["compliance_readiness"]
        assert "nist_800_57" in cr
        assert "fips_140" in cr
        assert "crypto_agility" in cr

    def test_has_next_steps(self):
        """Verify result has next steps."""
        result = get_crypto_readiness()
        assert "next_steps" in result
        assert len(result["next_steps"]) > 0
        # First step should be human authorization
        assert result["next_steps"][0]["step"] == 1
        assert "authorization" in result["next_steps"][0]["action"].lower()


class TestGetCryptoAlgorithms:
    """Test get_crypto_algorithms function."""

    def test_returns_dict(self):
        """Verify function returns a dictionary."""
        result = get_crypto_algorithms()
        assert isinstance(result, dict)

    def test_has_phase_indicator(self):
        """Verify result indicates Phase 8."""
        result = get_crypto_algorithms()
        assert "Phase 8" in result["phase"]

    def test_has_design_only_note(self):
        """Verify result notes this is design only."""
        result = get_crypto_algorithms()
        assert "DESIGN ONLY" in result["note"]

    def test_has_categories(self):
        """Verify result has algorithm categories."""
        result = get_crypto_algorithms()
        assert "categories" in result
        cats = result["categories"]
        assert "hashing" in cats
        assert "signing" in cats
        assert "encryption" in cats
        assert "key_exchange" in cats

    def test_hashing_sha256_implemented(self):
        """Verify SHA-256 is in implemented hashing."""
        result = get_crypto_algorithms()
        hashing = result["categories"]["hashing"]
        assert "SHA-256" in hashing["implemented"]

    def test_signing_not_implemented(self):
        """Verify no signing algorithms are implemented."""
        result = get_crypto_algorithms()
        signing = result["categories"]["signing"]
        assert signing["implemented"] == []

    def test_encryption_not_implemented(self):
        """Verify no encryption algorithms are implemented."""
        result = get_crypto_algorithms()
        encryption = result["categories"]["encryption"]
        assert encryption["implemented"] == []

    def test_has_planned_algorithms(self):
        """Verify planned algorithms are listed."""
        result = get_crypto_algorithms()
        signing = result["categories"]["signing"]
        assert len(signing["planned"]) > 0

    def test_has_pq_candidates(self):
        """Verify post-quantum candidates are listed."""
        result = get_crypto_algorithms()
        signing = result["categories"]["signing"]
        assert "post_quantum_candidates" in signing
        assert len(signing["post_quantum_candidates"]) > 0

    def test_has_agility_section(self):
        """Verify result has algorithm agility section."""
        result = get_crypto_algorithms()
        assert "agility" in result
        agility = result["agility"]
        assert "principle" in agility
        assert "versioning" in agility
        assert "deprecation" in agility


class TestNoCryptoOperations:
    """Test that the crypto module does NOT perform any crypto operations.

    CRITICAL: These tests verify that Phase 8 constraints are met.
    """

    def test_no_crypto_imports_in_module(self):
        """Verify no crypto library imports in crypto.py."""
        crypto_path = Path(__file__).parent.parent / "aictrl" / "commands" / "crypto.py"
        content = crypto_path.read_text()

        # Forbidden crypto imports
        forbidden_imports = [
            "import cryptography",
            "from cryptography",
            "import Crypto",
            "from Crypto",
            "import nacl",
            "from nacl",
            "import ssl",
            "import hmac",
            "import secrets",
            "from hashlib import",  # Only hashlib itself should be avoided in new code
        ]

        for forbidden in forbidden_imports:
            assert forbidden not in content, f"Found forbidden import: {forbidden}"

    def test_no_key_generation_code(self):
        """Verify no key generation code exists."""
        crypto_path = Path(__file__).parent.parent / "aictrl" / "commands" / "crypto.py"
        content = crypto_path.read_text()

        # Patterns that would indicate key generation
        generation_patterns = [
            "generate_key",
            "create_key",
            "new_key",
            "key_pair",
            "private_key",
            "secret_key",
            "os.urandom",
            "secrets.token",
            "random.SystemRandom",
        ]

        for pattern in generation_patterns:
            # Allow in comments/docstrings discussing what NOT to do
            lines = content.split("\n")
            for line in lines:
                if pattern in line and not line.strip().startswith("#") and '"""' not in line:
                    # Check if it's in a string context (acceptable)
                    if f'"{pattern}"' not in line and f"'{pattern}'" not in line:
                        assert False, f"Found potential key generation: {pattern} in line: {line}"

    def test_no_signing_code(self):
        """Verify no signing code exists."""
        crypto_path = Path(__file__).parent.parent / "aictrl" / "commands" / "crypto.py"
        content = crypto_path.read_text()

        # Patterns that would indicate signing operations
        signing_patterns = [
            ".sign(",
            ".verify(",
            "signer.",
            "signature =",
        ]

        for pattern in signing_patterns:
            lines = content.split("\n")
            for line in lines:
                if pattern in line and not line.strip().startswith("#"):
                    assert False, f"Found potential signing code: {pattern} in line: {line}"

    def test_no_encryption_code(self):
        """Verify no encryption code exists."""
        crypto_path = Path(__file__).parent.parent / "aictrl" / "commands" / "crypto.py"
        content = crypto_path.read_text()

        # Patterns that would indicate encryption operations
        encryption_patterns = [
            ".encrypt(",
            ".decrypt(",
            "cipher.",
            "ciphertext",
        ]

        for pattern in encryption_patterns:
            lines = content.split("\n")
            for line in lines:
                if pattern in line and not line.strip().startswith("#"):
                    assert False, f"Found potential encryption code: {pattern} in line: {line}"

    def test_no_hardware_access(self):
        """Verify no hardware security access code exists."""
        crypto_path = Path(__file__).parent.parent / "aictrl" / "commands" / "crypto.py"
        content = crypto_path.read_text()

        # Patterns that would indicate hardware access
        hw_patterns = [
            "/dev/tpm",
            "tpm2_",
            "pkcs11",
            "hsm.",
            "yubikey",
        ]

        for pattern in hw_patterns:
            lines = content.split("\n")
            for line in lines:
                if pattern in line and not line.strip().startswith("#") and '"""' not in line:
                    assert False, f"Found potential hardware access: {pattern} in line: {line}"


class TestDeterminism:
    """Test that crypto status output is structurally deterministic."""

    def test_status_structure_deterministic(self):
        """Verify status output has consistent structure."""
        result1 = get_crypto_status()
        result2 = get_crypto_status()

        # Same keys (structure)
        assert set(result1.keys()) == set(result2.keys())
        assert set(result1["configuration"].keys()) == set(result2["configuration"].keys())
        assert set(result1["keys"].keys()) == set(result2["keys"].keys())

    def test_readiness_structure_deterministic(self):
        """Verify readiness output has consistent structure."""
        result1 = get_crypto_readiness()
        result2 = get_crypto_readiness()

        # Same keys (structure)
        assert set(result1.keys()) == set(result2.keys())
        assert set(result1["assessment"].keys()) == set(result2["assessment"].keys())

    def test_algorithms_structure_deterministic(self):
        """Verify algorithms output has consistent structure."""
        result1 = get_crypto_algorithms()
        result2 = get_crypto_algorithms()

        # Same keys (structure)
        assert set(result1.keys()) == set(result2.keys())
        assert set(result1["categories"].keys()) == set(result2["categories"].keys())


class TestCLIIntegration:
    """Test CLI integration for crypto commands."""

    def test_cli_crypto_status(self):
        """Verify bbail crypto status command works."""
        result = subprocess.run(
            [sys.executable, "-m", "aictrl", "crypto", "status"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["status"] == STATUS_NOT_CONFIGURED

    def test_cli_crypto_readiness(self):
        """Verify bbail crypto readiness command works."""
        result = subprocess.run(
            [sys.executable, "-m", "aictrl", "crypto", "readiness"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["readiness_level"] == "design_complete"

    def test_cli_crypto_algorithms(self):
        """Verify bbail crypto algorithms command works."""
        result = subprocess.run(
            [sys.executable, "-m", "aictrl", "crypto", "algorithms"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert "categories" in output

    def test_cli_crypto_default_status(self):
        """Verify bbail crypto with no subcommand defaults to status."""
        result = subprocess.run(
            [sys.executable, "-m", "aictrl", "crypto"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["status"] == STATUS_NOT_CONFIGURED


class TestJsonSerializable:
    """Test that all outputs are JSON serializable."""

    def test_status_json_serializable(self):
        """Verify status output is JSON serializable."""
        result = get_crypto_status()
        # Should not raise
        json_str = json.dumps(result)
        # Should round-trip
        assert json.loads(json_str) == result

    def test_readiness_json_serializable(self):
        """Verify readiness output is JSON serializable."""
        result = get_crypto_readiness()
        # Should not raise
        json_str = json.dumps(result)
        # Should round-trip
        assert json.loads(json_str) == result

    def test_algorithms_json_serializable(self):
        """Verify algorithms output is JSON serializable."""
        result = get_crypto_algorithms()
        # Should not raise
        json_str = json.dumps(result)
        # Should round-trip
        assert json.loads(json_str) == result
