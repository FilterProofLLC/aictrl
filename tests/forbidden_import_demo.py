"""Forbidden import demonstration for Phase 19.

This file demonstrates what a forbidden import looks like for documentation.
It is NOT executed as a test - it exists to show enforcement patterns.

See docs/runtime/NEGATIVE_ENFORCEMENT_DEMOS.md for context.
"""

# This file intentionally contains a forbidden import pattern
# for demonstration purposes. It should NOT be executed.

# The following would be blocked by Host Safety Guard if executed:
# import requests  # FORBIDDEN: HTTP client module

# For testing, we just define metadata
DEMO_METADATA = {
    "purpose": "Document forbidden import patterns",
    "phase": 19,
    "invariants": ["INV-017"],
    "note": "This file exists for documentation, not execution",
}


def get_demo_info():
    """Return demo metadata."""
    return DEMO_METADATA
