"""Tests for bbail doctor command and schema validation."""

import json
import sys
from pathlib import Path

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.doctor import run_doctor

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


class TestDoctorCommand:
    """Tests for the doctor command."""

    def test_doctor_returns_dict(self):
        """Doctor should return a dictionary."""
        result = run_doctor()
        assert isinstance(result, dict)

    def test_doctor_has_required_fields(self):
        """Doctor should have all required fields."""
        result = run_doctor()
        required = ["timestamp_utc", "overall_status", "summary", "checks"]
        for field in required:
            assert field in result, f"Missing required field: {field}"

    def test_doctor_overall_status_valid(self):
        """Overall status should be pass, warn, or fail."""
        result = run_doctor()
        assert result["overall_status"] in ["pass", "warn", "fail"]

    def test_doctor_summary_has_counts(self):
        """Summary should have pass/warn/fail/total counts."""
        result = run_doctor()
        summary = result["summary"]
        assert "passed" in summary
        assert "warned" in summary
        assert "failed" in summary
        assert "total" in summary
        # Counts should add up
        assert summary["passed"] + summary["warned"] + summary["failed"] == summary["total"]

    def test_doctor_checks_is_list(self):
        """Checks should be a list."""
        result = run_doctor()
        assert isinstance(result["checks"], list)

    def test_doctor_check_has_required_fields(self):
        """Each check should have required fields."""
        result = run_doctor()
        for check in result["checks"]:
            assert "id" in check
            assert "description" in check
            assert "status" in check
            assert "evidence" in check
            assert check["status"] in ["pass", "warn", "fail"]

    def test_doctor_runs_expected_checks(self):
        """Doctor should run the expected checks."""
        result = run_doctor()
        check_ids = [c["id"] for c in result["checks"]]
        # Core system checks (always present)
        expected = [
            "python_version_ok",
            "disk_space_ok",
            "ssh_available",
            "git_available",
            "time_sync_status",
            "host_safety_enabled",
        ]
        for expected_id in expected:
            assert expected_id in check_ids, f"Missing expected check: {expected_id}"

        # Network checks: tailscale_cli_available is always present
        # (other Tailscale checks only run if tailscale CLI is found)
        assert "tailscale_cli_available" in check_ids

    @pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
    def test_doctor_validates_against_schema(self, schema_validator):
        """Doctor output should validate against schema."""
        result = run_doctor()
        schema_validator(result, "doctor")

    def test_doctor_is_json_serializable(self):
        """Doctor output should be JSON serializable."""
        result = run_doctor()
        json_str = json.dumps(result)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed == result
