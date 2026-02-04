"""aictrl boot command - boot measurement simulation.

This module provides SIMULATED boot measurements for the AICtrl boot chain model.

CRITICAL: This is SIMULATION ONLY.
- NO real boot operations
- NO kernel operations
- NO firmware interaction
- NO hardware access
- NO TPM operations

Measurements are computed deterministically from sandbox content.
See docs/security/MEASURED_STARTUP.md for specification.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..util.errors import AICtrlError


# Error codes for boot commands
BOOT_CONTEXT_ERROR = "AICTRL-7001"
BOOT_SANDBOX_ERROR = "AICTRL-7002"
BOOT_MEASUREMENT_ERROR = "AICTRL-7003"


# Simulation warning
SIMULATION_WARNING = (
    "Simulated measurements - not from real boot. "
    "See docs/security/MEASURED_STARTUP.md Section I."
)


# Measurement IDs and metadata
MEASUREMENT_POINTS = [
    {
        "id": "M1",
        "name": "bootloader_config",
        "component": "Bootloader Configuration",
        "source": "/boot/grub2/grub.cfg (simulated)",
        "stage": 1,
    },
    {
        "id": "M2",
        "name": "kernel_image",
        "component": "Kernel Image",
        "source": "/boot/vmlinuz-* (simulated)",
        "stage": 1,
    },
    {
        "id": "M3",
        "name": "kernel_cmdline",
        "component": "Kernel Command Line",
        "source": "/proc/cmdline (simulated)",
        "stage": 1,
    },
    {
        "id": "M4",
        "name": "initramfs",
        "component": "Initial RAM Filesystem",
        "source": "/boot/initramfs-* (simulated)",
        "stage": 2,
    },
    {
        "id": "M5",
        "name": "rootfs_commit",
        "component": "Root Filesystem",
        "source": "rpm-ostree deployment (simulated)",
        "stage": 3,
    },
    {
        "id": "M6",
        "name": "service_configs",
        "component": "Service Configurations",
        "source": "/etc base layer (simulated)",
        "stage": 3,
    },
]


def calculate_sha256(content: bytes) -> str:
    """Calculate SHA-256 hash of content.

    Args:
        content: Bytes to hash

    Returns:
        Hex-encoded lowercase SHA-256 hash
    """
    return hashlib.sha256(content).hexdigest()


def calculate_sha256_file(filepath: Path) -> str:
    """Calculate SHA-256 hash of a file.

    Args:
        filepath: Path to file

    Returns:
        Hex-encoded lowercase SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


def get_sandbox_path() -> Path:
    """Get path to AIOS sandbox rootfs.

    Returns:
        Path to sandbox rootfs

    Raises:
        AICtrlError: If sandbox not found
    """
    # Find repo root by looking for .git directory
    current = Path.cwd()
    while current != current.parent:
        if (current / ".git").exists():
            sandbox_path = current / "sandbox" / "aios-dev" / "rootfs"
            if sandbox_path.exists():
                return sandbox_path
            break
        current = current.parent

    raise AICtrlError(
        BOOT_SANDBOX_ERROR,
        "AIOS sandbox rootfs not found",
        cause="sandbox/aios-dev/rootfs directory does not exist",
        remediation=[
            "Run from repository root",
            "Ensure sandbox is initialized",
        ],
    )


def generate_simulated_content(measurement_id: str, sandbox_path: Path) -> bytes:
    """Generate deterministic simulated content for a measurement.

    This creates STABLE content that represents what would be measured
    during a real boot. Content is deterministic for reproducibility.

    Args:
        measurement_id: Measurement ID (M1-M6)
        sandbox_path: Path to sandbox rootfs

    Returns:
        Bytes representing simulated content
    """
    if measurement_id == "M1":
        # Bootloader configuration (simulated GRUB config)
        return b"""# AIOS Simulated GRUB Configuration
# This is deterministic simulation content
set default=0
set timeout=5
menuentry 'AIOS' {
    linux /boot/vmlinuz root=/dev/sda2 ro selinux=1
    initrd /boot/initramfs.img
}
"""

    elif measurement_id == "M2":
        # Kernel image (deterministic hash representing kernel)
        # In real boot, this would be the actual kernel binary
        return b"AIOS-SIMULATED-KERNEL-v1.0-DETERMINISTIC"

    elif measurement_id == "M3":
        # Kernel command line
        cmdline_path = sandbox_path / "proc" / "cmdline"
        if cmdline_path.exists():
            return cmdline_path.read_bytes()
        return b"root=/dev/sda2 ro selinux=1 quiet"

    elif measurement_id == "M4":
        # initramfs (deterministic representation)
        return b"AIOS-SIMULATED-INITRAMFS-v1.0-DETERMINISTIC"

    elif measurement_id == "M5":
        # Root filesystem commit hash
        # Compute from sandbox structure for determinism
        etc_path = sandbox_path / "etc"
        if etc_path.exists():
            # Hash the os-release file as proxy for rootfs identity
            os_release = etc_path / "os-release"
            if os_release.exists():
                return os_release.read_bytes()
        return b"AIOS-SIMULATED-ROOTFS-COMMIT-v1.0"

    elif measurement_id == "M6":
        # Service configurations
        # Merkle root of /etc (simplified: concatenate key files)
        etc_path = sandbox_path / "etc"
        content = b""
        if etc_path.exists():
            for filepath in sorted(etc_path.iterdir()):
                if filepath.is_file():
                    content += filepath.read_bytes()
        if not content:
            content = b"AIOS-SIMULATED-ETC-CONFIG-v1.0"
        return content

    else:
        return b"UNKNOWN-MEASUREMENT"


def compute_measurement(
    measurement_point: dict[str, Any],
    sandbox_path: Path,
    timestamp: str,
) -> dict[str, Any]:
    """Compute a single boot measurement.

    Args:
        measurement_point: Measurement metadata
        sandbox_path: Path to sandbox rootfs
        timestamp: Measurement timestamp

    Returns:
        Measurement record dictionary
    """
    content = generate_simulated_content(measurement_point["id"], sandbox_path)
    hash_value = calculate_sha256(content)

    return {
        "id": measurement_point["id"],
        "name": measurement_point["name"],
        "component": measurement_point["component"],
        "source": measurement_point["source"],
        "algorithm": "SHA-256",
        "hash": hash_value,
        "timestamp_utc": timestamp,
        "stage": measurement_point["stage"],
    }


def compute_combined_hash(measurements: list[dict[str, Any]]) -> str:
    """Compute combined hash from all measurements.

    The combined hash is SHA-256(M1 || M2 || M3 || M4 || M5 || M6)
    where || is concatenation of the individual hashes.

    Args:
        measurements: List of measurement records

    Returns:
        Combined SHA-256 hash
    """
    # Sort measurements by ID to ensure deterministic order
    sorted_measurements = sorted(measurements, key=lambda m: m["id"])

    # Concatenate all hashes
    combined = "".join(m["hash"] for m in sorted_measurements)

    # Hash the concatenation
    return calculate_sha256(combined.encode("utf-8"))


def simulate_boot_measurements(
    context: Optional[str] = None,
) -> dict[str, Any]:
    """Simulate boot measurements for AIOS.

    This is SIMULATION ONLY - no real boot operations.

    Args:
        context: Execution context override (must be aios-sandbox)

    Returns:
        Measurement log dictionary

    Raises:
        AICtrlError: If context is not sandbox or sandbox not found
    """
    # Validate context - only sandbox allowed for simulation
    if context and context != "aios-sandbox":
        raise AICtrlError(
            BOOT_CONTEXT_ERROR,
            f"Boot measurement simulation only valid in sandbox context",
            cause=f"Requested context '{context}' is not 'aios-sandbox'",
            remediation=[
                "Use --context aios-sandbox",
                "Boot measurement is simulation only",
            ],
        )

    # Get sandbox path
    sandbox_path = get_sandbox_path()

    # Generate boot ID and timestamps
    boot_id = str(uuid.uuid4())
    started_at = generate_timestamp()

    # Compute all measurements in order
    measurements = []
    for measurement_point in MEASUREMENT_POINTS:
        timestamp = generate_timestamp()
        measurement = compute_measurement(measurement_point, sandbox_path, timestamp)
        measurements.append(measurement)

    # Compute combined hash (boot identity)
    combined_hash = compute_combined_hash(measurements)

    completed_at = generate_timestamp()

    return {
        "simulated": True,
        "context": "aios-sandbox",
        "sandbox_path": str(sandbox_path),
        "measurement_log": {
            "version": "1.0",
            "boot_id": boot_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "measurements": measurements,
            "combined_hash": combined_hash,
        },
        "boot_identity": {
            "hash": combined_hash,
            "algorithm": "SHA-256",
            "measurement_count": len(measurements),
        },
        "warning": SIMULATION_WARNING,
    }


def verify_boot_identity(
    measurement_log: dict[str, Any],
    expected_hash: Optional[str] = None,
) -> dict[str, Any]:
    """Verify boot identity from measurement log.

    Recomputes combined hash and compares to stored value.

    Args:
        measurement_log: Measurement log from simulate_boot_measurements
        expected_hash: Optional expected hash to compare against

    Returns:
        Verification result dictionary
    """
    measurements = measurement_log.get("measurement_log", {}).get("measurements", [])
    stored_hash = measurement_log.get("measurement_log", {}).get("combined_hash")

    if not measurements:
        return {
            "valid": False,
            "error": "No measurements in log",
        }

    # Recompute combined hash
    computed_hash = compute_combined_hash(measurements)

    # Check self-consistency
    self_consistent = computed_hash == stored_hash

    # Check against expected if provided
    matches_expected = None
    if expected_hash:
        matches_expected = computed_hash == expected_hash

    result = {
        "valid": self_consistent,
        "computed_hash": computed_hash,
        "stored_hash": stored_hash,
        "self_consistent": self_consistent,
    }

    if expected_hash:
        result["expected_hash"] = expected_hash
        result["matches_expected"] = matches_expected
        result["valid"] = self_consistent and matches_expected

    return result


def get_measurement_summary(context: Optional[str] = None) -> dict[str, Any]:
    """Get a summary of boot measurements without full details.

    Args:
        context: Execution context override

    Returns:
        Summary dictionary
    """
    try:
        result = simulate_boot_measurements(context)
        return {
            "simulated": True,
            "context": result.get("context"),
            "boot_identity_hash": result.get("boot_identity", {}).get("hash"),
            "measurement_count": result.get("boot_identity", {}).get("measurement_count"),
            "warning": SIMULATION_WARNING,
        }
    except AICtrlError:
        raise
    except Exception as e:
        raise AICtrlError(
            BOOT_MEASUREMENT_ERROR,
            "Failed to compute boot measurements",
            cause=str(e),
            remediation=["Check sandbox path exists", "Run from repository root"],
        )
