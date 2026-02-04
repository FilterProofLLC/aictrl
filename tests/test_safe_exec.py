"""Tests for bbail host safety guard (safe_exec module)."""

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.util.safe_exec import (
    DENYLIST_PATTERNS,
    HOST_SAFETY_VIOLATION,
    HOST_SAFETY_OVERRIDE_INCOMPLETE,
    check_command_safety,
    check_override_validity,
    get_denylist_summary,
    get_safety_status,
    is_host_safety_enabled,
    is_risk_accepted,
    run_checked,
    set_risk_accepted,
)
from aictrl.util.errors import BbailError


class TestHostSafetyEnabled:
    """Tests for is_host_safety_enabled function."""

    def setup_method(self):
        """Reset risk acceptance before each test."""
        set_risk_accepted(False)

    def test_enabled_by_default(self):
        """Host safety should be ENABLED by default."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AICTRL_HOST_SAFETY", None)
            set_risk_accepted(False)
            assert is_host_safety_enabled()

    def test_enabled_when_env_not_set(self):
        """Host safety should be enabled when env var is not set."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            assert is_host_safety_enabled()

    def test_enabled_with_1(self):
        """Host safety should be enabled when set to '1'."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "1"}):
            assert is_host_safety_enabled()

    def test_enabled_with_true(self):
        """Host safety should be enabled when set to 'true'."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "true"}):
            assert is_host_safety_enabled()

    def test_enabled_with_random_value(self):
        """Host safety should be enabled for unrecognized values (fail safe)."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "random"}):
            set_risk_accepted(False)
            assert is_host_safety_enabled()

    def test_still_enabled_with_env_0_but_no_flag(self):
        """Host safety should remain enabled if env=0 but no CLI flag."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(False)
            # Without the flag, safety stays enabled
            assert is_host_safety_enabled()

    def test_disabled_only_with_both_env_and_flag(self):
        """Host safety disabled ONLY when BOTH env=0 AND flag passed."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(True)
            assert not is_host_safety_enabled()

    def test_disabled_with_false_and_flag(self):
        """Host safety disabled with env=false AND flag."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "false"}):
            set_risk_accepted(True)
            assert not is_host_safety_enabled()


class TestOverrideValidity:
    """Tests for check_override_validity function."""

    def setup_method(self):
        """Reset risk acceptance before each test."""
        set_risk_accepted(False)

    def test_no_error_when_safety_enabled(self):
        """Should not raise when safety is enabled (default)."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            # Should not raise
            check_override_validity()

    def test_error_when_env_0_without_flag(self):
        """Should raise error when env=0 but no CLI flag."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                check_override_validity()
            assert exc_info.value.code == HOST_SAFETY_OVERRIDE_INCOMPLETE
            assert "requires --i-accept-risk" in exc_info.value.cause

    def test_no_error_when_both_conditions_met(self):
        """Should not raise when both env=0 AND flag passed."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(True)
            # Should not raise
            check_override_validity()


class TestRiskAcceptance:
    """Tests for risk acceptance flag handling."""

    def setup_method(self):
        """Reset risk acceptance before each test."""
        set_risk_accepted(False)

    def test_default_not_accepted(self):
        """Risk should not be accepted by default."""
        set_risk_accepted(False)
        assert not is_risk_accepted()

    def test_can_set_accepted(self):
        """Should be able to set risk acceptance."""
        set_risk_accepted(True)
        assert is_risk_accepted()

    def test_can_unset_accepted(self):
        """Should be able to unset risk acceptance."""
        set_risk_accepted(True)
        set_risk_accepted(False)
        assert not is_risk_accepted()


class TestCheckCommandSafety:
    """Tests for check_command_safety function."""

    # Reboot/shutdown commands
    @pytest.mark.parametrize("cmd", [
        "reboot",
        "sudo reboot",
        "shutdown -h now",
        "sudo shutdown -r now",
        "poweroff",
        "halt",
        "init 0",
        "init 6",
        "systemctl reboot",
        "sudo systemctl poweroff",
    ])
    def test_blocks_reboot_shutdown(self, cmd):
        """Should block reboot/shutdown commands."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Package manager commands
    @pytest.mark.parametrize("cmd", [
        "apt install vim",
        "apt-get update",
        "sudo apt upgrade",
        "dpkg -i package.deb",
        "yum install httpd",
        "dnf install nginx",
        "sudo rpm -i package.rpm",
        "pacman -S package",
        "pip install --system package",
        "npm install -g package",
    ])
    def test_blocks_package_managers(self, cmd):
        """Should block package manager commands."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Kernel/bootloader commands
    @pytest.mark.parametrize("cmd", [
        "grub-install /dev/sda",
        "sudo update-grub",
        "dracut --force",
        "mkinitcpio -P",
        "modprobe nvidia",
        "sudo modprobe -r nvidia",
        "insmod module.ko",
        "rmmod module",
    ])
    def test_blocks_kernel_bootloader(self, cmd):
        """Should block kernel/bootloader modification commands."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Disk/partition commands
    @pytest.mark.parametrize("cmd", [
        "fdisk /dev/sda",
        "gdisk /dev/nvme0n1",
        "parted /dev/sda mkpart",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        "sudo mount /dev/sda1 /mnt",
        "umount /mnt",
        "lvchange -ay vg/lv",
        "vgchange -ay",
        "pvcreate /dev/sdb",
        "lvcreate -L 10G vg",
    ])
    def test_blocks_disk_operations(self, cmd):
        """Should block disk/partition operations."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Service control commands
    @pytest.mark.parametrize("cmd", [
        "systemctl start nginx",
        "systemctl stop sshd",
        "sudo systemctl restart docker",
        "systemctl enable firewalld",
        "systemctl disable cups",
        "systemctl mask NetworkManager",
        "service apache2 start",
        "sudo service mysql restart",
    ])
    def test_blocks_service_control(self, cmd):
        """Should block service control commands."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Dangerous file operations
    @pytest.mark.parametrize("cmd", [
        "rm -rf /",
        "sudo rm -r /etc",
        "chmod 777 /usr",
        "sudo chown root:root /etc/passwd",
    ])
    def test_blocks_dangerous_file_ops(self, cmd):
        """Should block dangerous file operations."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Network configuration
    @pytest.mark.parametrize("cmd", [
        "iptables -A INPUT -j DROP",
        "sudo nft add rule inet filter input drop",
        "ip link set eth0 down",
        "ip addr add 10.0.0.1/24 dev eth0",
        "ip route del default",
    ])
    def test_blocks_network_config(self, cmd):
        """Should block network configuration commands."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # User/group modifications
    @pytest.mark.parametrize("cmd", [
        "useradd testuser",
        "userdel -r user",
        "usermod -aG sudo user",
        "groupadd newgroup",
        "passwd root",
    ])
    def test_blocks_user_management(self, cmd):
        """Should block user/group management commands."""
        result = check_command_safety(cmd)
        assert result is not None, f"Should block: {cmd}"

    # Safe commands that should NOT be blocked
    @pytest.mark.parametrize("cmd", [
        "ls -la",
        "cat /etc/os-release",
        "echo hello",
        "python --version",
        "pip install --user package",
        "pip list",
        "npm list",
        "git status",
        "hostname",
        "df -h",
        "free -m",
        "ps aux",
        "top -bn1",
        "journalctl --no-pager -n 100",
        "dmesg | head",
        "systemctl status sshd",
        "ip addr show",
        "ip route show",
        "ls /etc",
        "cat /proc/meminfo",
        "uname -a",
    ])
    def test_allows_safe_commands(self, cmd):
        """Should allow safe/read-only commands."""
        result = check_command_safety(cmd)
        assert result is None, f"Should allow: {cmd}"


class TestRunChecked:
    """Tests for run_checked function."""

    def setup_method(self):
        """Reset risk acceptance before each test."""
        set_risk_accepted(False)

    def test_blocks_dangerous_command_by_default(self):
        """Dangerous commands should be blocked by default (safety on)."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                run_checked("sudo reboot")
            assert exc_info.value.code == HOST_SAFETY_VIOLATION

    def test_allows_safe_command_by_default(self):
        """Safe commands should execute by default."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            result = run_checked("echo hello")
            assert result.returncode == 0
            assert "hello" in result.stdout

    def test_blocks_when_env_0_without_flag(self):
        """Should block dangerous commands when env=0 but no flag."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(False)
            # Safety remains enabled because flag not passed
            with pytest.raises(BbailError) as exc_info:
                run_checked("sudo reboot")
            assert exc_info.value.code == HOST_SAFETY_VIOLATION

    def test_allows_dangerous_when_properly_disabled(self):
        """Should allow dangerous commands when properly disabled."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(True)
            # Use a command that would be blocked but mock the actual execution
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.MagicMock(returncode=0, stdout="mocked")
                result = run_checked("sudo reboot")
                mock_run.assert_called_once()

    def test_error_has_correct_structure(self):
        """BbailError should have proper structure for JSON output."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                run_checked("apt install vim")
            error = exc_info.value
            error_dict = error.to_dict()
            assert "error" in error_dict
            assert error_dict["error"]["code"] == HOST_SAFETY_VIOLATION
            assert "message" in error_dict["error"]
            assert "cause" in error_dict["error"]
            assert "remediation" in error_dict["error"]
            assert len(error_dict["error"]["remediation"]) > 0

    def test_list_command_is_checked(self):
        """Commands passed as lists should also be checked."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                run_checked(["sudo", "systemctl", "restart", "nginx"])
            assert exc_info.value.code == HOST_SAFETY_VIOLATION

    def test_captures_output_by_default(self):
        """Output should be captured by default."""
        result = run_checked("echo test123")
        assert "test123" in result.stdout

    def test_respects_timeout(self):
        """Timeout should be respected."""
        import subprocess
        with pytest.raises(subprocess.TimeoutExpired):
            run_checked("sleep 10", timeout=0.1)


class TestGetDenylistSummary:
    """Tests for get_denylist_summary function."""

    def test_returns_list(self):
        """Should return a list."""
        result = get_denylist_summary()
        assert isinstance(result, list)

    def test_has_expected_fields(self):
        """Each entry should have pattern and description."""
        result = get_denylist_summary()
        for entry in result:
            assert "pattern" in entry
            assert "description" in entry

    def test_matches_denylist_length(self):
        """Summary should match denylist length."""
        result = get_denylist_summary()
        assert len(result) == len(DENYLIST_PATTERNS)


class TestGetSafetyStatus:
    """Tests for get_safety_status function."""

    def setup_method(self):
        """Reset risk acceptance before each test."""
        set_risk_accepted(False)

    def test_returns_dict(self):
        """Should return a dictionary."""
        result = get_safety_status()
        assert isinstance(result, dict)

    def test_has_required_fields(self):
        """Should have all required fields."""
        result = get_safety_status()
        assert "host_safety_enabled" in result
        assert "env_var" in result
        assert "risk_flag_passed" in result
        assert "denylist_pattern_count" in result

    def test_shows_enabled_by_default(self):
        """Should show enabled by default."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            result = get_safety_status()
            assert result["host_safety_enabled"] is True

    def test_shows_disabled_when_properly_overridden(self):
        """Should show disabled when properly overridden."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(True)
            result = get_safety_status()
            assert result["host_safety_enabled"] is False
            assert result["risk_flag_passed"] is True


class TestRefusalBehavior:
    """Tests verifying refusal behavior produces correct JSON output."""

    def setup_method(self):
        """Reset risk acceptance before each test."""
        set_risk_accepted(False)

    def test_refusal_is_json_serializable(self):
        """Refusal error should be JSON serializable."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                run_checked("dnf install httpd")
            error_dict = exc_info.value.to_dict()
            # Should not raise
            json_str = json.dumps(error_dict)
            assert isinstance(json_str, str)
            # Should round-trip
            parsed = json.loads(json_str)
            assert parsed == error_dict

    def test_incomplete_override_is_json_serializable(self):
        """Incomplete override error should be JSON serializable."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": "0"}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                check_override_validity()
            error_dict = exc_info.value.to_dict()
            json_str = json.dumps(error_dict)
            parsed = json.loads(json_str)
            assert parsed["error"]["code"] == HOST_SAFETY_OVERRIDE_INCOMPLETE

    def test_refusal_includes_actionable_remediation(self):
        """Refusal should include actionable remediation steps."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                run_checked("mkfs.ext4 /dev/sda1")
            remediation = exc_info.value.remediation
            assert len(remediation) >= 2
            # Should mention how to disable
            assert any("AICTRL_HOST_SAFETY" in r for r in remediation)
            assert any("--i-accept-risk" in r for r in remediation)

    @pytest.mark.parametrize("blocked_cmd,expected_category", [
        ("reboot", "reboot"),
        ("apt install foo", "package"),
        ("systemctl restart nginx", "service"),
        ("fdisk /dev/sda", "partition"),
        ("modprobe nvidia", "kernel"),
    ])
    def test_refusal_message_is_descriptive(self, blocked_cmd, expected_category):
        """Refusal message should describe what was blocked."""
        with mock.patch.dict(os.environ, {"AICTRL_HOST_SAFETY": ""}):
            set_risk_accepted(False)
            with pytest.raises(BbailError) as exc_info:
                run_checked(blocked_cmd)
            message_lower = exc_info.value.message.lower()
            cause_lower = exc_info.value.cause.lower()
            # The description or matched text should give context
            combined = message_lower + cause_lower
            assert any(word in combined for word in [expected_category, blocked_cmd.split()[0]])
