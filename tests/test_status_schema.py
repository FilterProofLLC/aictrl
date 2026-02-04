"""Tests for bbail status command and schema validation."""

import json
import sys
from pathlib import Path

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.status import get_status

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


class TestStatusCommand:
    """Tests for the status command."""

    def test_status_returns_dict(self):
        """Status should return a dictionary."""
        result = get_status()
        assert isinstance(result, dict)

    def test_status_has_required_fields(self):
        """Status should have all required fields."""
        result = get_status()
        required = ["timestamp_utc", "host", "os", "resources", "network", "notes"]
        for field in required:
            assert field in result, f"Missing required field: {field}"

    def test_status_timestamp_format(self):
        """Timestamp should be ISO 8601 format."""
        result = get_status()
        ts = result["timestamp_utc"]
        assert "T" in ts, "Timestamp should be ISO 8601 format"
        assert ts.endswith("+00:00") or ts.endswith("Z"), "Timestamp should be UTC"

    def test_status_host_has_hostname(self):
        """Host object should have hostname."""
        result = get_status()
        assert "hostname" in result["host"]
        assert isinstance(result["host"]["hostname"], str)

    def test_status_notes_is_list(self):
        """Notes should be a list of strings."""
        result = get_status()
        assert isinstance(result["notes"], list)
        for note in result["notes"]:
            assert isinstance(note, str)

    @pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
    def test_status_validates_against_schema(self, schema_validator):
        """Status output should validate against schema."""
        result = get_status()
        schema_validator(result, "status")

    def test_status_is_json_serializable(self):
        """Status output should be JSON serializable."""
        result = get_status()
        # Should not raise
        json_str = json.dumps(result)
        assert isinstance(json_str, str)
        # Should round-trip
        parsed = json.loads(json_str)
        assert parsed == result
