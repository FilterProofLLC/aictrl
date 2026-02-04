"""Tests for bbail sandbox command."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add bbail to path for testing
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aictrl.cli import main, cmd_sandbox_status, cmd_sandbox_start, cmd_sandbox_stop
from aictrl.commands.sandbox import (
    get_sandbox_status,
    start_sandbox,
    stop_sandbox,
    SANDBOX_NOT_FOUND,
    SANDBOX_IMPORT_FAILED,
    SANDBOX_START_FAILED,
    SANDBOX_STOP_FAILED,
)
from aictrl.util.errors import BbailError


class TestGetSandboxStatus:
    """Tests for sandbox status retrieval."""

    def test_returns_status_dict(self):
        """Test that status returns a dict with expected keys."""
        mock_sandbox = MagicMock()
        mock_sandbox.status.return_value = {
            "sandbox": {"name": "aios-dev", "state": "stopped", "running": False},
            "system": {"hostname": "aios-sandbox"},
            "safety": {"host_safety_enabled": True},
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = get_sandbox_status()

        assert "sandbox" in result
        assert "system" in result
        assert "safety" in result
        mock_sandbox.status.assert_called_once()

    def test_raises_on_import_failure(self):
        """Test that import failure raises BbailError."""
        with patch(
            "aictrl.commands.sandbox._get_sandbox",
            side_effect=BbailError(
                code=SANDBOX_NOT_FOUND,
                message="Module not found",
                cause="test",
                remediation=[],
            ),
        ):
            with pytest.raises(BbailError) as exc_info:
                get_sandbox_status()
            assert exc_info.value.code == SANDBOX_NOT_FOUND


class TestStartSandbox:
    """Tests for sandbox start."""

    def test_start_success(self):
        """Test successful sandbox start."""
        mock_sandbox = MagicMock()
        mock_sandbox.start.return_value = {
            "success": True,
            "message": "Sandbox started",
            "state": {"state": "running"},
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = start_sandbox()

        assert result["success"] is True
        mock_sandbox.start.assert_called_once()

    def test_start_already_running(self):
        """Test start when sandbox is already running."""
        mock_sandbox = MagicMock()
        mock_sandbox.start.return_value = {
            "success": False,
            "message": "Sandbox is already running",
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            with pytest.raises(BbailError) as exc_info:
                start_sandbox()
            assert exc_info.value.code == SANDBOX_START_FAILED


class TestStopSandbox:
    """Tests for sandbox stop."""

    def test_stop_success(self):
        """Test successful sandbox stop."""
        mock_sandbox = MagicMock()
        mock_sandbox.stop.return_value = {
            "success": True,
            "message": "Sandbox stopped",
            "state": {"state": "stopped"},
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = stop_sandbox()

        assert result["success"] is True
        mock_sandbox.stop.assert_called_once()

    def test_stop_not_running(self):
        """Test stop when sandbox is not running."""
        mock_sandbox = MagicMock()
        mock_sandbox.stop.return_value = {
            "success": False,
            "message": "Sandbox is not running",
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            with pytest.raises(BbailError) as exc_info:
                stop_sandbox()
            assert exc_info.value.code == SANDBOX_STOP_FAILED


class TestSandboxCLI:
    """Tests for sandbox CLI commands."""

    def test_sandbox_status_cli(self, capsys):
        """Test bbail sandbox status CLI."""
        mock_sandbox = MagicMock()
        mock_sandbox.status.return_value = {
            "sandbox": {"name": "aios-dev", "state": "stopped"},
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = main(["sandbox", "status"])

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["sandbox"]["name"] == "aios-dev"

    def test_sandbox_start_cli(self, capsys):
        """Test bbail sandbox start CLI."""
        mock_sandbox = MagicMock()
        mock_sandbox.start.return_value = {
            "success": True,
            "message": "Sandbox started",
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = main(["sandbox", "start"])

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["success"] is True

    def test_sandbox_stop_cli(self, capsys):
        """Test bbail sandbox stop CLI."""
        mock_sandbox = MagicMock()
        mock_sandbox.stop.return_value = {
            "success": True,
            "message": "Sandbox stopped",
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = main(["sandbox", "stop"])

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["success"] is True

    def test_sandbox_no_subcommand_shows_status(self, capsys):
        """Test that sandbox with no subcommand defaults to status."""
        mock_sandbox = MagicMock()
        mock_sandbox.status.return_value = {
            "sandbox": {"name": "aios-dev", "state": "stopped"},
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = main(["sandbox"])

        assert result == 0
        mock_sandbox.status.assert_called_once()

    def test_sandbox_error_returns_json(self, capsys):
        """Test that errors are returned as JSON."""
        with patch(
            "aictrl.cli.get_sandbox_status",
            side_effect=BbailError(
                code=SANDBOX_NOT_FOUND,
                message="Module not found",
                cause="test cause",
                remediation=["Install the module"],
            ),
        ):
            result = main(["sandbox", "status"])

        assert result == 1
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # BbailError.to_dict() wraps in "error" key
        assert output["error"]["code"] == SANDBOX_NOT_FOUND
        assert "remediation" in output["error"]

    def test_sandbox_status_pretty(self, capsys):
        """Test bbail sandbox status --pretty."""
        mock_sandbox = MagicMock()
        mock_sandbox.status.return_value = {
            "sandbox": {"name": "aios-dev"},
        }

        with patch("aictrl.commands.sandbox._get_sandbox", return_value=mock_sandbox):
            result = main(["sandbox", "status", "--pretty"])

        assert result == 0
        captured = capsys.readouterr()
        # Pretty output has newlines and indentation
        assert "\n" in captured.out
        assert "  " in captured.out
