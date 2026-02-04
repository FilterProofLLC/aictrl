"""Pytest configuration and fixtures for bbail tests."""

import json
from pathlib import Path

import pytest

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


SCHEMAS_DIR = Path(__file__).parent.parent / "aictrl" / "schemas"


def load_schema(name: str) -> dict:
    """Load a JSON schema by name."""
    schema_path = SCHEMAS_DIR / f"{name}.schema.json"
    with open(schema_path) as f:
        return json.load(f)


def validate_against_schema(data: dict, schema_name: str) -> None:
    """Validate data against a named schema.

    Raises:
        jsonschema.ValidationError: If validation fails.
        ImportError: If jsonschema is not installed.
    """
    if not HAS_JSONSCHEMA:
        pytest.skip("jsonschema not installed")

    schema = load_schema(schema_name)
    jsonschema.validate(data, schema)


@pytest.fixture
def schema_validator():
    """Return schema validation helper function."""
    return validate_against_schema
