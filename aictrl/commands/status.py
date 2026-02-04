"""bbail status command - collect system status information."""

import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any


def get_status() -> dict[str, Any]:
    """Collect system status information.

    Returns only safe, unprivileged host information.
    Fields that cannot be determined are set to null with a note.

    Returns:
        Dictionary matching status.schema.json.
    """
    notes = []

    # Timestamp
    timestamp_utc = datetime.now(timezone.utc).isoformat()

    # Host information
    host = {
        "hostname": _safe_get(socket.gethostname, "unknown"),
        "kernel": _safe_get(platform.release, None),
        "arch": _safe_get(platform.machine, None),
    }

    # OS information
    os_info = _get_os_info(notes)

    # Resource information
    resources = _get_resources(notes)

    # Network information
    network = _get_network_info(notes)

    return {
        "timestamp_utc": timestamp_utc,
        "host": host,
        "os": os_info,
        "resources": resources,
        "network": network,
        "notes": notes,
    }


def _safe_get(func, default):
    """Safely call a function, returning default on exception."""
    try:
        return func()
    except Exception:
        return default


def _get_os_info(notes: list) -> dict[str, Any]:
    """Get OS information."""
    os_name = None
    os_version = None

    # Try platform first
    try:
        os_name = platform.system()
        os_version = platform.version()
    except Exception:
        pass

    # Try /etc/os-release for Linux
    if os_name == "Linux":
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        os_version = line.split("=", 1)[1].strip().strip('"')
        except (FileNotFoundError, PermissionError):
            notes.append("Could not read /etc/os-release")
        except Exception as e:
            notes.append(f"Error reading OS info: {e}")

    return {
        "name": os_name,
        "version": os_version,
    }


def _get_resources(notes: list) -> dict[str, Any]:
    """Get resource information (CPU, memory)."""
    cpu_count = None
    mem_total_bytes = None

    # CPU count
    try:
        cpu_count = os.cpu_count()
    except Exception:
        notes.append("Could not determine CPU count")

    # Memory - try /proc/meminfo on Linux
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    # Format: MemTotal:       16384000 kB
                    parts = line.split()
                    if len(parts) >= 2:
                        mem_kb = int(parts[1])
                        mem_total_bytes = mem_kb * 1024
                    break
    except (FileNotFoundError, PermissionError):
        notes.append("Could not read /proc/meminfo")
    except Exception as e:
        notes.append(f"Error reading memory info: {e}")

    return {
        "cpu_count": cpu_count,
        "mem_total_bytes": mem_total_bytes,
    }


def _get_network_info(notes: list) -> dict[str, Any]:
    """Get basic network information."""
    has_ipv4 = None
    default_route_present = None

    # Check for IPv4 connectivity by trying to create a socket
    try:
        # This doesn't actually send data, just checks if we can create a route
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        # Connect to a public DNS (doesn't send data for UDP)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
        has_ipv4 = local_ip != "0.0.0.0"
        default_route_present = True
    except Exception:
        has_ipv4 = False
        default_route_present = False
        notes.append("No IPv4 route to external network detected")

    return {
        "has_ipv4": has_ipv4,
        "default_route_present": default_route_present,
    }
