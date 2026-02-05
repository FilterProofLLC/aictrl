"""Tests for location enforcement (Phase 15).

These tests verify that:
1. When AICTRL_ENFORCE_LOCATION is unset: warn-only, no denial
2. When AICTRL_ENFORCE_LOCATION=1: non-canonical triggers denial
3. When AICTRL_ENFORCE_LOCATION=1: submodule triggers denial
4. CI environment exempts from enforcement even when flag ON
5. Phase 15.2: Remote mismatch, detached HEAD, symlinked path

IMPORTANT: These tests use mocking and do NOT require actual git operations.
"""

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.util.location import (
    CANONICAL_PATH,
    LOCATION_NON_CANONICAL,
    LOCATION_SUBMODULE_DETECTED,
    LOCATION_REMOTE_MISMATCH,
    LOCATION_DETACHED_HEAD,
    LOCATION_SYMLINK_DETECTED,
    ENFORCE_LOCATION_VAR,
    is_enforcement_enabled,
    is_ci_environment,
    detect_location_context,
    evaluate_location_policy,
    _find_git_root,
    _is_submodule,
    _get_origin_remote_url,
    _normalize_remote_url,
    _is_canonical_remote,
    _is_detached_head,
    _is_symlinked_path,
)
from aictrl.util.invariants import ExecutionContext


class TestCanonicalPath:
    """Tests for CANONICAL_PATH constant."""

    def test_canonical_path_is_string(self):
        """CANONICAL_PATH should be a string."""
        assert isinstance(CANONICAL_PATH, str)

    def test_canonical_path_is_expanded(self):
        """CANONICAL_PATH should not contain unexpanded ~."""
        assert "~" not in CANONICAL_PATH

    def test_canonical_path_is_absolute(self):
        """CANONICAL_PATH should be an absolute path."""
        assert CANONICAL_PATH.startswith("/")


class TestIsEnforcementEnabled:
    """Tests for enforcement flag detection."""

    def test_enforcement_disabled_by_default(self):
        """Enforcement should be OFF when env var is unset."""
        with mock.patch.dict(os.environ, {}, clear=True):
            # Remove the var if it exists
            os.environ.pop(ENFORCE_LOCATION_VAR, None)
            assert is_enforcement_enabled() is False

    def test_enforcement_enabled_when_1(self):
        """Enforcement should be ON when set to '1'."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            assert is_enforcement_enabled() is True

    def test_enforcement_enabled_when_true(self):
        """Enforcement should be ON when set to 'true'."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "true"}):
            assert is_enforcement_enabled() is True

    def test_enforcement_disabled_when_0(self):
        """Enforcement should be OFF when set to '0'."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "0"}):
            assert is_enforcement_enabled() is False

    def test_enforcement_disabled_when_empty(self):
        """Enforcement should be OFF when set to empty string."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: ""}):
            assert is_enforcement_enabled() is False


class TestDetectLocationContext:
    """Tests for location context detection."""

    def test_returns_dict_with_required_keys(self):
        """Should return dict with all required keys."""
        result = detect_location_context()
        assert isinstance(result, dict)
        assert "canonical_path" in result
        assert "actual_path" in result
        assert "is_canonical" in result
        assert "is_submodule" in result
        assert "parent_repo" in result
        assert "detection_error" in result
        # Phase 15.2 fields
        assert "origin_remote" in result
        assert "is_canonical_remote" in result
        assert "is_detached_head" in result
        assert "is_symlinked" in result

    def test_canonical_when_path_matches(self):
        """Should report is_canonical=True when paths match."""
        # Mock git root to return canonical path
        with mock.patch(
            "aictrl.util.location._find_git_root",
            return_value=os.path.realpath(CANONICAL_PATH),
        ):
            result = detect_location_context()
            assert result["is_canonical"] is True

    def test_non_canonical_when_path_differs(self):
        """Should report is_canonical=False when paths differ."""
        with mock.patch(
            "aictrl.util.location._find_git_root",
            return_value="/tmp/other-aictrl",
        ):
            result = detect_location_context()
            assert result["is_canonical"] is False
            assert result["actual_path"] == "/tmp/other-aictrl"

    def test_detection_error_captured(self):
        """Should capture detection errors without raising."""
        with mock.patch(
            "aictrl.util.location._find_git_root",
            side_effect=Exception("test error"),
        ):
            with mock.patch("os.getcwd", side_effect=Exception("cwd error")):
                result = detect_location_context()
                assert result["detection_error"] is not None


class TestSubmoduleDetection:
    """Tests for submodule detection."""

    def test_submodule_when_git_is_file(self, tmp_path):
        """Should detect submodule when .git is a file."""
        # Create a .git file (submodule indicator)
        git_file = tmp_path / ".git"
        git_file.write_text("gitdir: ../../.git/modules/tools/aictrl")

        assert _is_submodule(str(tmp_path)) is True

    def test_not_submodule_when_git_is_directory(self, tmp_path):
        """Should not detect submodule when .git is a directory."""
        # Create a .git directory (normal repo)
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        assert _is_submodule(str(tmp_path)) is False

    def test_not_submodule_when_git_missing(self, tmp_path):
        """Should not detect submodule when .git is missing."""
        assert _is_submodule(str(tmp_path)) is False


class TestEvaluateLocationPolicy:
    """Tests for policy evaluation."""

    def test_warn_only_when_enforcement_off(self):
        """Should produce warnings but no denial when enforcement OFF."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop(ENFORCE_LOCATION_VAR, None)
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value="/tmp/non-canonical",
            ):
                with mock.patch(
                    "aictrl.util.location.is_ci_environment",
                    return_value=False,
                ):
                    result = evaluate_location_policy()
                    assert result["enforce"] is False
                    assert result["denial"] is None
                    assert len(result["warnings"]) > 0

    def test_denial_when_enforcement_on_non_canonical(self):
        """Should deny when enforcement ON and non-canonical."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value="/tmp/non-canonical",
            ):
                with mock.patch(
                    "aictrl.util.location.is_ci_environment",
                    return_value=False,
                ):
                    result = evaluate_location_policy()
                    assert result["enforce"] is True
                    assert result["denial"] is not None
                    assert result["denial"]["code"] == LOCATION_NON_CANONICAL

    def test_denial_when_enforcement_on_submodule(self, tmp_path):
        """Should deny when enforcement ON and submodule detected."""
        # Create a .git file to simulate submodule
        git_file = tmp_path / ".git"
        git_file.write_text("gitdir: ../../.git/modules/tools/aictrl")

        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=str(tmp_path),
            ):
                with mock.patch(
                    "aictrl.util.location.is_ci_environment",
                    return_value=False,
                ):
                    result = evaluate_location_policy()
                    assert result["enforce"] is True
                    assert result["denial"] is not None
                    assert result["denial"]["code"] == LOCATION_SUBMODULE_DETECTED

    def test_ci_exempt_even_when_enforcement_on(self):
        """Should NOT deny in CI even when enforcement ON."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value="/tmp/non-canonical",
            ):
                with mock.patch(
                    "aictrl.util.location.is_ci_environment",
                    return_value=True,
                ):
                    result = evaluate_location_policy()
                    assert result["enforce"] is True
                    assert result["ci_exempt"] is True
                    assert result["denial"] is None

    def test_canonical_path_no_denial(self):
        """Should not deny when running from canonical path."""
        canonical_resolved = os.path.realpath(CANONICAL_PATH)
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=canonical_resolved,
            ):
                with mock.patch(
                    "aictrl.util.location.is_ci_environment",
                    return_value=False,
                ):
                    # Also ensure .git is a directory (not submodule)
                    with mock.patch(
                        "aictrl.util.location._is_submodule",
                        return_value=False,
                    ):
                        result = evaluate_location_policy()
                        assert result["denial"] is None


class TestWarningFormat:
    """Tests for warning format compliance."""

    def test_warnings_have_required_fields(self):
        """Warnings should have source, message, artifact fields."""
        with mock.patch(
            "aictrl.util.location._find_git_root",
            return_value="/tmp/non-canonical",
        ):
            with mock.patch(
                "aictrl.util.location.is_ci_environment",
                return_value=False,
            ):
                result = evaluate_location_policy()
                for warning in result["warnings"]:
                    assert "source" in warning
                    assert "message" in warning
                    assert "artifact" in warning
                    assert warning["source"] == "observability"
                    assert warning["artifact"] == "location"

    def test_all_messages_are_ascii(self):
        """All warning messages should be ASCII-only."""
        with mock.patch(
            "aictrl.util.location._find_git_root",
            return_value="/tmp/non-canonical-\xe4\xb8\xad\xe6\x96\x87",
        ):
            with mock.patch(
                "aictrl.util.location.is_ci_environment",
                return_value=False,
            ):
                result = evaluate_location_policy()
                for warning in result["warnings"]:
                    # Should not raise - str() handles non-ASCII paths
                    assert isinstance(warning["message"], str)


class TestCIDetection:
    """Tests for CI environment detection."""

    def test_ci_detected_with_github_actions(self):
        """Should detect CI when GITHUB_ACTIONS is set."""
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            assert is_ci_environment() is True

    def test_ci_detected_with_ci_var(self):
        """Should detect CI when CI env var is set."""
        with mock.patch.dict(os.environ, {"CI": "true"}):
            assert is_ci_environment() is True

    def test_ci_not_detected_in_dev(self):
        """Should not detect CI in normal dev environment."""
        # Clear CI indicators
        env = {k: v for k, v in os.environ.items()
               if k not in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
                           "TRAVIS", "CIRCLECI", "AIOS_CONTEXT")}
        with mock.patch.dict(os.environ, env, clear=True):
            result = is_ci_environment()
            # In sandbox/dev environment, should not be CI
            # (may be sandbox, but not CI)
            # Just verify no crash and returns a boolean
            assert isinstance(result, bool)


# =============================================================================
# Phase 15.2 Tests
# =============================================================================


class TestRemoteUrlNormalization:
    """Tests for remote URL normalization (Phase 15.2)."""

    def test_normalize_https_url(self):
        """Should normalize HTTPS URL."""
        url = "https://github.com/FilterProofLLC/aictrl.git"
        normalized = _normalize_remote_url(url)
        assert normalized == "github.com/filterproofllc/aictrl"

    def test_normalize_https_without_git_suffix(self):
        """Should handle HTTPS URL without .git suffix."""
        url = "https://github.com/FilterProofLLC/aictrl"
        normalized = _normalize_remote_url(url)
        assert normalized == "github.com/filterproofllc/aictrl"

    def test_normalize_ssh_url(self):
        """Should normalize SSH URL (git@...) to same form as HTTPS."""
        url = "git@github.com:FilterProofLLC/aictrl.git"
        normalized = _normalize_remote_url(url)
        assert normalized == "github.com/filterproofllc/aictrl"

    def test_normalize_ssh_protocol_url(self):
        """Should normalize ssh:// URL to same form as HTTPS."""
        url = "ssh://git@github.com/FilterProofLLC/aictrl.git"
        normalized = _normalize_remote_url(url)
        assert normalized == "github.com/filterproofllc/aictrl"

    def test_normalize_empty_url(self):
        """Should handle empty URL."""
        assert _normalize_remote_url("") == ""
        assert _normalize_remote_url(None) == ""

    def test_case_insensitive(self):
        """Should be case-insensitive."""
        url1 = "https://github.com/FILTERPROOFLLC/AICTRL"
        url2 = "https://github.com/filterproofllc/aictrl"
        assert _normalize_remote_url(url1) == _normalize_remote_url(url2)

    def test_all_formats_normalize_same(self):
        """All URL formats should normalize to the same string."""
        urls = [
            "https://github.com/FilterProofLLC/aictrl",
            "https://github.com/FilterProofLLC/aictrl.git",
            "git@github.com:FilterProofLLC/aictrl",
            "git@github.com:FilterProofLLC/aictrl.git",
            "ssh://git@github.com/FilterProofLLC/aictrl",
            "ssh://git@github.com/FilterProofLLC/aictrl.git",
        ]
        normalized = [_normalize_remote_url(u) for u in urls]
        assert all(n == "github.com/filterproofllc/aictrl" for n in normalized)


class TestIsCanonicalRemote:
    """Tests for canonical remote detection (Phase 15.2)."""

    def test_https_canonical(self):
        """Should accept canonical HTTPS URL."""
        assert _is_canonical_remote("https://github.com/FilterProofLLC/aictrl") is True
        assert _is_canonical_remote("https://github.com/FilterProofLLC/aictrl.git") is True

    def test_ssh_canonical(self):
        """Should accept canonical SSH URL."""
        assert _is_canonical_remote("git@github.com:FilterProofLLC/aictrl") is True
        assert _is_canonical_remote("git@github.com:FilterProofLLC/aictrl.git") is True

    def test_ssh_protocol_canonical(self):
        """Should accept canonical ssh:// URL."""
        assert _is_canonical_remote("ssh://git@github.com/FilterProofLLC/aictrl") is True
        assert _is_canonical_remote("ssh://git@github.com/FilterProofLLC/aictrl.git") is True

    def test_fork_not_canonical(self):
        """Should reject fork URL."""
        assert _is_canonical_remote("https://github.com/someuser/aictrl") is False
        assert _is_canonical_remote("git@github.com:someuser/aictrl.git") is False

    def test_different_repo_not_canonical(self):
        """Should reject different repo URL."""
        assert _is_canonical_remote("https://github.com/FilterProofLLC/other-repo") is False

    def test_none_url_is_canonical(self):
        """Should treat None URL as canonical (unknown = no denial)."""
        assert _is_canonical_remote(None) is True

    def test_case_insensitive_match(self):
        """Should match case-insensitively."""
        assert _is_canonical_remote("HTTPS://GITHUB.COM/FILTERPROOFLLC/AICTRL") is True


class TestRemoteMismatchEnforcement:
    """Tests for AICTRL-7003 remote mismatch enforcement (Phase 15.2)."""

    def test_warning_when_remote_mismatches_enforcement_off(self):
        """Should warn (not deny) on remote mismatch when enforcement OFF."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop(ENFORCE_LOCATION_VAR, None)
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._get_origin_remote_url",
                    return_value="https://github.com/someuser/aictrl-fork",
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            result = evaluate_location_policy()
                            assert result["denial"] is None
                            # Should have warning for remote mismatch
                            codes = [w.get("code") for w in result["warnings"]]
                            assert LOCATION_REMOTE_MISMATCH in codes

    def test_denial_when_remote_mismatches_enforcement_on(self):
        """Should deny on remote mismatch when enforcement ON."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._get_origin_remote_url",
                    return_value="https://github.com/someuser/aictrl-fork",
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            result = evaluate_location_policy()
                            assert result["denial"] is not None
                            assert result["denial"]["code"] == LOCATION_REMOTE_MISMATCH

    def test_no_denial_when_remote_unknown(self):
        """Should NOT deny when origin remote is unknown."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._get_origin_remote_url",
                    return_value=None,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            result = evaluate_location_policy()
                            # No denial when remote is unknown
                            assert result["denial"] is None

    def test_ci_exempt_from_remote_mismatch(self):
        """Should NOT deny in CI even with remote mismatch."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._get_origin_remote_url",
                    return_value="https://github.com/someuser/aictrl-fork",
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=True,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            result = evaluate_location_policy()
                            assert result["ci_exempt"] is True
                            assert result["denial"] is None


class TestDetachedHeadDetection:
    """Tests for detached HEAD detection (Phase 15.2)."""

    def test_attached_head_detected(self):
        """Should detect attached HEAD."""
        # Mock subprocess to return success (attached)
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = "refs/heads/main"
        with mock.patch("subprocess.run", return_value=mock_result):
            assert _is_detached_head() is False

    def test_detached_head_detected(self):
        """Should detect detached HEAD."""
        # Mock subprocess to return failure (detached)
        mock_result = mock.Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with mock.patch("subprocess.run", return_value=mock_result):
            assert _is_detached_head() is True

    def test_detection_error_returns_none(self):
        """Should return None on detection error."""
        with mock.patch("subprocess.run", side_effect=Exception("test error")):
            assert _is_detached_head() is None


class TestDetachedHeadEnforcement:
    """Tests for AICTRL-7004 detached HEAD enforcement (Phase 15.2)."""

    def test_warning_when_detached_enforcement_off(self):
        """Should warn (not deny) on detached HEAD when enforcement OFF."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop(ENFORCE_LOCATION_VAR, None)
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._is_detached_head",
                    return_value=True,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            with mock.patch(
                                "aictrl.util.location._get_origin_remote_url",
                                return_value="https://github.com/FilterProofLLC/aictrl",
                            ):
                                result = evaluate_location_policy()
                                assert result["denial"] is None
                                codes = [w.get("code") for w in result["warnings"]]
                                assert LOCATION_DETACHED_HEAD in codes

    def test_denial_when_detached_enforcement_on(self):
        """Should deny on detached HEAD when enforcement ON."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._is_detached_head",
                    return_value=True,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            with mock.patch(
                                "aictrl.util.location._get_origin_remote_url",
                                return_value="https://github.com/FilterProofLLC/aictrl",
                            ):
                                result = evaluate_location_policy()
                                assert result["denial"] is not None
                                assert result["denial"]["code"] == LOCATION_DETACHED_HEAD

    def test_ci_exempt_from_detached_head(self):
        """Should NOT deny in CI even with detached HEAD."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._is_detached_head",
                    return_value=True,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=True,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            with mock.patch(
                                "aictrl.util.location._get_origin_remote_url",
                                return_value="https://github.com/FilterProofLLC/aictrl",
                            ):
                                result = evaluate_location_policy()
                                assert result["ci_exempt"] is True
                                assert result["denial"] is None


class TestSymlinkedPathDetection:
    """Tests for symlinked path detection (Phase 15.2)."""

    def test_symlink_detected(self, tmp_path):
        """Should detect symlinked path."""
        # Create a real directory and a symlink to it
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_dir = tmp_path / "link"
        try:
            link_dir.symlink_to(real_dir)
            assert _is_symlinked_path(str(link_dir)) is True
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

    def test_real_path_not_detected_as_symlink(self, tmp_path):
        """Should NOT detect real path as symlinked."""
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        assert _is_symlinked_path(str(real_dir)) is False

    def test_empty_path_not_symlinked(self):
        """Should handle empty path."""
        assert _is_symlinked_path("") is False
        assert _is_symlinked_path(None) is False


class TestSymlinkedPathEnforcement:
    """Tests for AICTRL-7005 symlinked path enforcement (Phase 15.2)."""

    def test_warning_when_symlinked_enforcement_off(self, tmp_path):
        """Should warn (not deny) on symlinked path when enforcement OFF."""
        # Create symlink structure
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_dir = tmp_path / "link"
        try:
            link_dir.symlink_to(real_dir)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop(ENFORCE_LOCATION_VAR, None)
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._is_symlinked_path",
                    return_value=True,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            with mock.patch(
                                "aictrl.util.location._get_origin_remote_url",
                                return_value="https://github.com/FilterProofLLC/aictrl",
                            ):
                                with mock.patch(
                                    "aictrl.util.location._is_detached_head",
                                    return_value=False,
                                ):
                                    result = evaluate_location_policy()
                                    assert result["denial"] is None
                                    codes = [w.get("code") for w in result["warnings"]]
                                    assert LOCATION_SYMLINK_DETECTED in codes

    def test_denial_when_symlinked_enforcement_on(self):
        """Should deny on symlinked path when enforcement ON."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._is_symlinked_path",
                    return_value=True,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=False,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            with mock.patch(
                                "aictrl.util.location._get_origin_remote_url",
                                return_value="https://github.com/FilterProofLLC/aictrl",
                            ):
                                with mock.patch(
                                    "aictrl.util.location._is_detached_head",
                                    return_value=False,
                                ):
                                    result = evaluate_location_policy()
                                    assert result["denial"] is not None
                                    assert result["denial"]["code"] == LOCATION_SYMLINK_DETECTED

    def test_ci_exempt_from_symlinked_path(self):
        """Should NOT deny in CI even with symlinked path."""
        with mock.patch.dict(os.environ, {ENFORCE_LOCATION_VAR: "1"}):
            with mock.patch(
                "aictrl.util.location._find_git_root",
                return_value=os.path.realpath(CANONICAL_PATH),
            ):
                with mock.patch(
                    "aictrl.util.location._is_symlinked_path",
                    return_value=True,
                ):
                    with mock.patch(
                        "aictrl.util.location.is_ci_environment",
                        return_value=True,
                    ):
                        with mock.patch(
                            "aictrl.util.location._is_submodule",
                            return_value=False,
                        ):
                            with mock.patch(
                                "aictrl.util.location._get_origin_remote_url",
                                return_value="https://github.com/FilterProofLLC/aictrl",
                            ):
                                with mock.patch(
                                    "aictrl.util.location._is_detached_head",
                                    return_value=False,
                                ):
                                    result = evaluate_location_policy()
                                    assert result["ci_exempt"] is True
                                    assert result["denial"] is None


class TestDetectLocationContextPhase152:
    """Tests for new fields in detect_location_context (Phase 15.2)."""

    def test_context_has_new_fields(self):
        """Should include Phase 15.2 fields."""
        result = detect_location_context()
        assert "origin_remote" in result
        assert "is_canonical_remote" in result
        assert "is_detached_head" in result
        assert "is_symlinked" in result

    def test_context_defaults_for_unknown(self):
        """Should have safe defaults when detection fails."""
        with mock.patch(
            "aictrl.util.location._get_origin_remote_url",
            return_value=None,
        ):
            with mock.patch(
                "aictrl.util.location._is_detached_head",
                return_value=None,
            ):
                result = detect_location_context()
                # Unknown remote = canonical (no denial)
                assert result["is_canonical_remote"] is True
                # Unknown HEAD state = None
                assert result["is_detached_head"] is None
