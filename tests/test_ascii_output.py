"""Test ASCII-only output enforcement for CLI.

This test ensures CLI output contains only ASCII characters (0x00-0x7F),
which is required for audit, ESA, and DoD/NIST ingestion compliance.

Non-ASCII characters (emojis, Unicode symbols) must not appear in
default CLI output. If Unicode output is needed, it must be behind
an explicit opt-in flag.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest


def is_ascii_only(text: str) -> bool:
    """Check if text contains only ASCII characters (0x00-0x7F)."""
    try:
        text.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


def get_non_ascii_chars(text: str) -> list[tuple[int, str, str]]:
    """Find non-ASCII characters in text.

    Returns:
        List of (position, character, hex_code) tuples for each non-ASCII char.
    """
    non_ascii = []
    for i, char in enumerate(text):
        if ord(char) > 127:
            non_ascii.append((i, char, hex(ord(char))))
    return non_ascii


def run_aictrl_command(*args) -> tuple[str, str, int]:
    """Run aictrl command and return stdout, stderr, returncode."""
    # Use the module directly to avoid shim issues
    cmd = [sys.executable, "-m", "aictrl"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


class TestASCIIOnlyOutput:
    """Test that CLI output contains only ASCII characters."""

    def test_version_output_is_ascii(self):
        """aictrl version output must be ASCII-only."""
        stdout, stderr, rc = run_aictrl_command("version")
        assert rc == 0, f"version command failed: {stderr}"

        combined = stdout + stderr
        assert is_ascii_only(combined), (
            f"Non-ASCII characters in version output: {get_non_ascii_chars(combined)}"
        )

        # Verify it's valid JSON
        data = json.loads(stdout)
        assert "version" in data

    def test_version_flag_output_is_ascii(self):
        """aictrl --version output must be ASCII-only."""
        stdout, stderr, rc = run_aictrl_command("--version")
        assert rc == 0, f"--version flag failed: {stderr}"

        combined = stdout + stderr
        assert is_ascii_only(combined), (
            f"Non-ASCII characters in --version output: {get_non_ascii_chars(combined)}"
        )

    def test_doctor_output_is_ascii(self):
        """aictrl doctor output must be ASCII-only."""
        stdout, stderr, rc = run_aictrl_command("doctor")
        # doctor may return non-zero if checks fail, but output should still be ASCII

        combined = stdout + stderr
        assert is_ascii_only(combined), (
            f"Non-ASCII characters in doctor output: {get_non_ascii_chars(combined)}"
        )

        # Verify it's valid JSON
        data = json.loads(stdout)
        assert "overall_status" in data
        assert data["overall_status"] in ("pass", "warn", "fail")

    def test_doctor_pretty_output_is_ascii(self):
        """aictrl doctor --pretty output must be ASCII-only."""
        stdout, stderr, rc = run_aictrl_command("doctor", "--pretty")

        combined = stdout + stderr
        assert is_ascii_only(combined), (
            f"Non-ASCII characters in doctor --pretty output: {get_non_ascii_chars(combined)}"
        )

    def test_status_output_is_ascii(self):
        """aictrl status output must be ASCII-only."""
        stdout, stderr, rc = run_aictrl_command("status")
        assert rc == 0, f"status command failed: {stderr}"

        combined = stdout + stderr
        assert is_ascii_only(combined), (
            f"Non-ASCII characters in status output: {get_non_ascii_chars(combined)}"
        )

        # Verify it's valid JSON
        data = json.loads(stdout)
        assert "timestamp_utc" in data

    def test_help_output_is_ascii(self):
        """aictrl --help output must be ASCII-only."""
        stdout, stderr, rc = run_aictrl_command("--help")
        assert rc == 0, f"--help failed: {stderr}"

        combined = stdout + stderr
        assert is_ascii_only(combined), (
            f"Non-ASCII characters in help output: {get_non_ascii_chars(combined)}"
        )

    def test_doctor_checks_use_ascii_status_values(self):
        """Doctor check status values must be ASCII text (pass/warn/fail)."""
        stdout, _, _ = run_aictrl_command("doctor")
        data = json.loads(stdout)

        # Verify status values are plain ASCII text, not Unicode symbols
        valid_statuses = {"pass", "warn", "fail"}

        assert data["overall_status"] in valid_statuses, (
            f"Invalid overall_status: {data['overall_status']!r}"
        )

        for check in data.get("checks", []):
            status = check.get("status")
            assert status in valid_statuses, (
                f"Check {check.get('id')!r} has invalid status: {status!r}"
            )
            # Ensure no Unicode checkmarks or X marks in evidence
            evidence = check.get("evidence", "")
            assert is_ascii_only(evidence), (
                f"Non-ASCII in check {check.get('id')!r} evidence: "
                f"{get_non_ascii_chars(evidence)}"
            )


class TestASCIISourceCode:
    """Test that source code files contain only ASCII characters."""

    def test_aictrl_package_is_ascii_only(self):
        """All Python files in aictrl package must be ASCII-only.

        This prevents accidental introduction of Unicode characters
        that could appear in error messages or output strings.
        """
        aictrl_dir = Path(__file__).parent.parent / "aictrl"
        non_ascii_files = []

        for py_file in aictrl_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            if not is_ascii_only(content):
                chars = get_non_ascii_chars(content)
                non_ascii_files.append((py_file.name, chars[:5]))  # First 5

        assert not non_ascii_files, (
            f"Non-ASCII characters found in source files: {non_ascii_files}"
        )
