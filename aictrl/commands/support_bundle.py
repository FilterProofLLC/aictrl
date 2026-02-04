"""aictrl support-bundle command - diagnostic collection."""

import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .status import get_status
from .doctor import run_doctor
from .. import __version__
from ..util.safe_exec import run_checked


def create_support_bundle(output_path: str = None) -> dict[str, Any]:
    """Create a support bundle with diagnostic information.

    Args:
        output_path: Directory to write bundle to. Defaults to current directory.

    Returns:
        Dictionary with bundle path and metadata.
    """
    if output_path is None:
        output_path = os.getcwd()

    output_path = Path(output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
    bundle_name = f"aictrl_support_bundle_{timestamp_str}.tar.gz"
    bundle_path = output_path / bundle_name

    command_log = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create subdirectories
        (tmpdir / "aictrl").mkdir()
        (tmpdir / "meta").mkdir()
        (tmpdir / "logs").mkdir()

        # Collect aictrl outputs
        _collect_aictrl_outputs(tmpdir, command_log)

        # Collect metadata
        _collect_metadata(tmpdir, timestamp, command_log)

        # Attempt to collect logs (best effort, no sudo)
        _collect_logs(tmpdir, command_log)

        # Create tarball
        with tarfile.open(bundle_path, "w:gz") as tar:
            for item in tmpdir.iterdir():
                tar.add(item, arcname=item.name)

    return {
        "success": True,
        "bundle_path": str(bundle_path),
        "created_at": timestamp.isoformat(),
        "files_collected": len(command_log),
    }


def _collect_aictrl_outputs(tmpdir: Path, command_log: list) -> None:
    """Collect aictrl command outputs."""
    # Version
    version_data = {
        "name": "aictrl",
        "version": __version__,
        "commit": _get_git_commit(),
    }
    _write_json(tmpdir / "aictrl" / "version.json", version_data)
    command_log.append("aictrl version -> aictrl/version.json")

    # Status
    try:
        status_data = get_status()
        _write_json(tmpdir / "aictrl" / "status.json", status_data)
        command_log.append("aictrl status -> aictrl/status.json")
    except Exception as e:
        _write_json(tmpdir / "aictrl" / "status.json", {"error": str(e)})
        command_log.append(f"aictrl status -> ERROR: {e}")

    # Doctor
    try:
        doctor_data = run_doctor()
        _write_json(tmpdir / "aictrl" / "doctor.json", doctor_data)
        command_log.append("aictrl doctor -> aictrl/doctor.json")
    except Exception as e:
        _write_json(tmpdir / "aictrl" / "doctor.json", {"error": str(e)})
        command_log.append(f"aictrl doctor -> ERROR: {e}")


def _collect_metadata(tmpdir: Path, timestamp: datetime, command_log: list) -> None:
    """Collect bundle metadata."""
    # Created timestamp
    created_at = tmpdir / "meta" / "created_at.txt"
    created_at.write_text(timestamp.isoformat() + "\n")
    command_log.append("meta/created_at.txt")

    # Command log (write at the end)
    # We'll update this after all collection is done


def _collect_logs(tmpdir: Path, command_log: list) -> None:
    """Attempt to collect system logs (best effort, no sudo)."""
    import subprocess  # for TimeoutExpired exception
    logs_dir = tmpdir / "logs"
    notes = []

    # Try journalctl (may fail without permissions for full logs)
    try:
        result = run_checked(
            ["journalctl", "-n", "500", "--no-pager", "-q"],
            shell=False,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            (logs_dir / "journal_recent.txt").write_text(result.stdout)
            command_log.append("journalctl -n 500 -> logs/journal_recent.txt")
        else:
            notes.append("journalctl: limited or no output available")
    except FileNotFoundError:
        notes.append("journalctl: command not found")
    except subprocess.TimeoutExpired:
        notes.append("journalctl: timeout")
    except Exception as e:
        notes.append(f"journalctl: {e}")

    # Try dmesg (may fail without permissions)
    try:
        result = run_checked(
            ["dmesg", "--ctime", "-T"],
            shell=False,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            (logs_dir / "dmesg.txt").write_text(result.stdout)
            command_log.append("dmesg -> logs/dmesg.txt")
        else:
            # Try without options
            result = run_checked(
                ["dmesg"],
                shell=False,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                (logs_dir / "dmesg.txt").write_text(result.stdout)
                command_log.append("dmesg -> logs/dmesg.txt")
            else:
                notes.append("dmesg: permission denied or no output")
    except FileNotFoundError:
        notes.append("dmesg: command not found")
    except subprocess.TimeoutExpired:
        notes.append("dmesg: timeout")
    except Exception as e:
        notes.append(f"dmesg: {e}")

    # Write notes about what couldn't be collected
    if notes:
        notes_path = logs_dir / "collection_notes.txt"
        notes_path.write_text("\n".join(notes) + "\n")
        command_log.append("logs/collection_notes.txt (collection issues)")


def _get_git_commit() -> str:
    """Get current git commit hash if available."""
    try:
        result = run_checked(
            ["git", "rev-parse", "--short", "HEAD"],
            shell=False,
            timeout=5,
            cwd=Path(__file__).parent.parent.parent,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _write_json(path: Path, data: Any) -> None:
    """Write data as JSON to file."""
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
        f.write("\n")
