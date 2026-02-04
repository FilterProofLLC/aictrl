"""Tests for bbail pr command and PR workflow."""

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.pr import (
    PR_ON_MAIN_BRANCH,
    PR_NO_COMMITS_AHEAD,
    PR_GH_NOT_AUTHENTICATED,
    PR_GIT_PUSH_FAILED,
    PR_CREATE_FAILED,
    PR_BOTH_METHODS_FAILED,
    GRAPHQL_TRANSIENT_ERRORS,
    current_branch,
    commits_ahead_of_main,
    ensure_gh_auth,
    push_branch,
    create_pr,
    create_pr_via_api,
    get_repo_info,
    is_graphql_transient_error,
    run_pr_create,
)
from aictrl.util.errors import BbailError


class MockCompletedProcess:
    """Mock subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestCurrentBranch:
    """Tests for current_branch function."""

    def test_returns_branch_name(self):
        """Should return the current branch name."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="feature/test-branch\n"
            )
            result = current_branch()
            assert result == "feature/test-branch"
            # Verify the command was called (run_checked adds shell=False, timeout, check)
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]

    def test_raises_on_failure(self):
        """Should raise BbailError if git command fails."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=128, stderr="fatal: not a git repository"
            )
            with pytest.raises(BbailError) as exc_info:
                current_branch()
            assert exc_info.value.code == PR_CREATE_FAILED
            assert "not a git repository" in exc_info.value.cause


class TestCommitsAheadOfMain:
    """Tests for commits_ahead_of_main function."""

    def test_returns_commit_count(self):
        """Should return number of commits ahead."""
        with mock.patch("subprocess.run") as mock_run:
            # First call is fetch, second is rev-list
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="3\n"),  # rev-list
            ]
            result = commits_ahead_of_main()
            assert result == 3

    def test_returns_zero_for_no_commits(self):
        """Should return 0 when no commits ahead."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="0\n"),  # rev-list
            ]
            result = commits_ahead_of_main()
            assert result == 0

    def test_falls_back_to_local_main(self):
        """Should fall back to local main if origin/main fails."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=128, stderr="unknown revision"),  # origin/main
                MockCompletedProcess(returncode=0, stdout="2\n"),  # main
            ]
            result = commits_ahead_of_main()
            assert result == 2

    def test_handles_fetch_failure_gracefully(self):
        """Should continue even if fetch fails (offline)."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=1, stderr="network error"),  # fetch fails
                MockCompletedProcess(returncode=0, stdout="5\n"),  # rev-list succeeds
            ]
            result = commits_ahead_of_main()
            assert result == 5

    def test_returns_zero_for_invalid_output(self):
        """Should return 0 if output cannot be parsed as int."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="invalid\n"),  # rev-list
            ]
            result = commits_ahead_of_main()
            assert result == 0


class TestEnsureGhAuth:
    """Tests for ensure_gh_auth function."""

    def test_returns_true_when_authenticated(self):
        """Should return True when gh is authenticated."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="Logged in to github.com"
            )
            result = ensure_gh_auth()
            assert result is True

    def test_raises_when_not_authenticated(self):
        """Should raise BbailError when gh is not authenticated."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=1, stderr="not logged in"),  # auth status
                MockCompletedProcess(returncode=0, stdout="/usr/bin/gh"),  # which gh
            ]
            with pytest.raises(BbailError) as exc_info:
                ensure_gh_auth()
            assert exc_info.value.code == PR_GH_NOT_AUTHENTICATED
            assert "not authenticated" in exc_info.value.message.lower()

    def test_raises_when_gh_not_installed(self):
        """Should raise BbailError when gh is not installed."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=1, stderr="not logged in"),  # auth status
                MockCompletedProcess(returncode=1),  # which gh fails
            ]
            with pytest.raises(BbailError) as exc_info:
                ensure_gh_auth()
            assert exc_info.value.code == PR_GH_NOT_AUTHENTICATED
            assert "not installed" in exc_info.value.message.lower()


class TestPushBranch:
    """Tests for push_branch function."""

    def test_returns_true_on_success(self):
        """Should return (True, output) on success."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0,
                stdout="Branch pushed",
                stderr="To github.com:user/repo.git"
            )
            success, output = push_branch("feature/test")
            assert success is True
            assert "github.com" in output

    def test_raises_on_failure(self):
        """Should raise BbailError on push failure."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=1, stderr="Permission denied (publickey)"
            )
            with pytest.raises(BbailError) as exc_info:
                push_branch("feature/test")
            assert exc_info.value.code == PR_GIT_PUSH_FAILED
            assert "Permission denied" in exc_info.value.cause


class TestGraphQLErrorDetection:
    """Tests for is_graphql_transient_error function."""

    def test_detects_head_sha_blank_error(self):
        """Should detect 'Head sha can't be blank' as transient."""
        assert is_graphql_transient_error("Head sha can't be blank")

    def test_detects_base_sha_blank_error(self):
        """Should detect 'Base sha can't be blank' as transient."""
        assert is_graphql_transient_error("Base sha can't be blank")

    def test_detects_no_commits_between_error(self):
        """Should detect 'No commits between' as transient."""
        assert is_graphql_transient_error("No commits between main and feature")

    def test_detects_head_ref_must_be_branch_error(self):
        """Should detect 'Head ref must be a branch' as transient."""
        assert is_graphql_transient_error("Head ref must be a branch")

    def test_case_insensitive_matching(self):
        """Should match errors case-insensitively."""
        assert is_graphql_transient_error("HEAD SHA CAN'T BE BLANK")
        assert is_graphql_transient_error("head sha can't be blank")

    def test_matches_embedded_in_larger_message(self):
        """Should match when error is embedded in larger message."""
        msg = "GraphQL: Head sha can't be blank, Base sha can't be blank (createPullRequest)"
        assert is_graphql_transient_error(msg)

    def test_does_not_match_other_errors(self):
        """Should not match unrelated errors."""
        assert not is_graphql_transient_error("Permission denied")
        assert not is_graphql_transient_error("Authentication failed")
        assert not is_graphql_transient_error("Resource not found")


class TestGetRepoInfo:
    """Tests for get_repo_info function."""

    def test_parses_ssh_url(self):
        """Should parse owner/repo from SSH URL."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="git@github.com:owner/repo.git\n"
            )
            owner, repo = get_repo_info()
            assert owner == "owner"
            assert repo == "repo"

    def test_parses_https_url_with_git_suffix(self):
        """Should parse owner/repo from HTTPS URL with .git suffix."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="https://github.com/myorg/myrepo.git\n"
            )
            owner, repo = get_repo_info()
            assert owner == "myorg"
            assert repo == "myrepo"

    def test_parses_https_url_without_git_suffix(self):
        """Should parse owner/repo from HTTPS URL without .git suffix."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="https://github.com/user/project\n"
            )
            owner, repo = get_repo_info()
            assert owner == "user"
            assert repo == "project"

    def test_raises_on_no_remote(self):
        """Should raise BbailError if no origin remote."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=1, stderr="fatal: No such remote 'origin'"
            )
            with pytest.raises(BbailError) as exc_info:
                get_repo_info()
            assert exc_info.value.code == PR_CREATE_FAILED

    def test_raises_on_unparseable_url(self):
        """Should raise BbailError if URL format is unexpected."""
        with mock.patch("subprocess.run") as mock_run:
            # URL without owner/repo structure
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="just-a-single-word\n"
            )
            with pytest.raises(BbailError) as exc_info:
                get_repo_info()
            assert exc_info.value.code == PR_CREATE_FAILED
            assert "parse" in exc_info.value.message.lower()


class TestCreatePrViaApi:
    """Tests for create_pr_via_api function."""

    def test_returns_pr_details_on_success(self):
        """Should return PR details with method_used=gh_api_fallback."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),  # get_repo_info
                MockCompletedProcess(
                    returncode=0,
                    stdout='{"html_url": "https://github.com/owner/repo/pull/99", "number": 99}'
                ),  # gh api
            ]
            result = create_pr_via_api("Test PR", "Body", "feature/test")
            assert result["success"] is True
            assert result["method_used"] == "gh_api_fallback"
            assert result["pr_url"] == "https://github.com/owner/repo/pull/99"
            assert result["pr_number"] == 99
            assert "warnings" in result
            assert len(result["warnings"]) > 0

    def test_raises_on_already_exists(self):
        """Should raise BbailError if PR already exists."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),
                MockCompletedProcess(
                    returncode=1,
                    stderr="Validation Failed: A pull request already exists"
                ),
            ]
            with pytest.raises(BbailError) as exc_info:
                create_pr_via_api("Test PR", "Body", "feature/test")
            assert exc_info.value.code == PR_CREATE_FAILED
            assert "already exists" in exc_info.value.message.lower()

    def test_raises_on_api_failure(self):
        """Should raise BbailError on API failure."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),
                MockCompletedProcess(returncode=1, stderr="API rate limit exceeded"),
            ]
            with pytest.raises(BbailError) as exc_info:
                create_pr_via_api("Test PR", "Body", "feature/test")
            assert exc_info.value.code == PR_CREATE_FAILED

    def test_raises_on_invalid_json_response(self):
        """Should raise BbailError if API returns invalid JSON."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),
                MockCompletedProcess(returncode=0, stdout="not valid json"),
            ]
            with pytest.raises(BbailError) as exc_info:
                create_pr_via_api("Test PR", "Body", "feature/test")
            assert exc_info.value.code == PR_CREATE_FAILED
            assert "parse" in exc_info.value.message.lower()


class TestCreatePr:
    """Tests for create_pr function."""

    def test_returns_pr_details_on_success(self):
        """Should return PR details on success with method_used."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch
                MockCompletedProcess(
                    returncode=0,
                    stdout="https://github.com/user/repo/pull/42\n"
                ),  # gh pr create
            ]
            result = create_pr("Test PR", "Test body")
            assert result["success"] is True
            assert result["method_used"] == "gh_pr_create"
            assert result["pr_url"] == "https://github.com/user/repo/pull/42"
            assert result["pr_number"] == 42
            assert result["title"] == "Test PR"
            assert result["warnings"] == []

    def test_raises_on_already_exists(self):
        """Should raise specific error if PR already exists."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),
                MockCompletedProcess(
                    returncode=1,
                    stderr="a pull request already exists for user:feature/test"
                ),
            ]
            with pytest.raises(BbailError) as exc_info:
                create_pr("Test PR", "Test body")
            assert exc_info.value.code == PR_CREATE_FAILED
            assert "already exists" in exc_info.value.message.lower()

    def test_raises_on_other_failure(self):
        """Should raise BbailError on non-transient failures."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),
                MockCompletedProcess(returncode=1, stderr="Permission denied"),
            ]
            with pytest.raises(BbailError) as exc_info:
                create_pr("Test PR", "Test body")
            assert exc_info.value.code == PR_CREATE_FAILED

    def test_fallback_on_graphql_error(self):
        """Should fallback to gh api on GraphQL transient error."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch
                MockCompletedProcess(
                    returncode=1,
                    stderr="GraphQL: Head sha can't be blank, Base sha can't be blank"
                ),  # gh pr create fails
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),  # get_repo_info
                MockCompletedProcess(
                    returncode=0,
                    stdout='{"html_url": "https://github.com/owner/repo/pull/77", "number": 77}'
                ),  # gh api succeeds
            ]
            result = create_pr("Test PR", "Test body")
            assert result["success"] is True
            assert result["method_used"] == "gh_api_fallback"
            assert result["pr_number"] == 77
            assert len(result["warnings"]) > 0
            assert "fallback" in result["warnings"][0].lower()

    def test_both_methods_fail_raises_special_error(self):
        """Should raise BBAIL-5025 if both gh pr create and gh api fail."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch
                MockCompletedProcess(
                    returncode=1,
                    stderr="GraphQL: Head sha can't be blank"
                ),  # gh pr create fails
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),  # get_repo_info
                MockCompletedProcess(
                    returncode=1,
                    stderr="API error: server unavailable"
                ),  # gh api also fails
            ]
            with pytest.raises(BbailError) as exc_info:
                create_pr("Test PR", "Test body")
            assert exc_info.value.code == PR_BOTH_METHODS_FAILED
            assert "gh pr create" in exc_info.value.cause
            assert "gh api" in exc_info.value.cause


class TestRunPrCreate:
    """Tests for run_pr_create workflow function."""

    def test_refuses_on_main_branch(self):
        """Should refuse to create PR from main branch."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="main\n"
            )
            with pytest.raises(BbailError) as exc_info:
                run_pr_create("Test", "Body")
            assert exc_info.value.code == PR_ON_MAIN_BRANCH
            assert "main" in exc_info.value.message.lower()

    def test_refuses_on_master_branch(self):
        """Should refuse to create PR from master branch."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="master\n"
            )
            with pytest.raises(BbailError) as exc_info:
                run_pr_create("Test", "Body")
            assert exc_info.value.code == PR_ON_MAIN_BRANCH

    def test_refuses_with_no_commits_ahead(self):
        """Should refuse if no commits ahead of main."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="0\n"),  # commits_ahead
            ]
            with pytest.raises(BbailError) as exc_info:
                run_pr_create("Test", "Body")
            assert exc_info.value.code == PR_NO_COMMITS_AHEAD

    def test_dry_run_returns_success(self):
        """Dry run should return success without creating PR."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="3\n"),  # commits_ahead
                MockCompletedProcess(returncode=0),  # gh auth status
            ]
            result = run_pr_create("Test", "Body", dry_run=True)
            assert result["success"] is True
            assert result["dry_run"] is True
            assert result["method_used"] is None
            assert result["warnings"] == []
            assert len(result["checks"]) == 3

    def test_full_workflow_success(self):
        """Should complete full workflow successfully."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch in run_pr_create
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="3\n"),  # commits_ahead
                MockCompletedProcess(returncode=0),  # gh auth status
                MockCompletedProcess(returncode=0, stdout="pushed\n"),  # git push
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch for gh pr create
                MockCompletedProcess(returncode=0, stdout="https://github.com/user/repo/pull/42\n"),  # gh pr create
            ]
            result = run_pr_create("Test PR", "Body")
            assert result["success"] is True
            assert result["pr_number"] == 42
            assert result["method_used"] == "gh_pr_create"
            assert result["warnings"] == []

    def test_full_workflow_with_fallback(self):
        """Should complete workflow using fallback when gh pr create fails."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch
                MockCompletedProcess(returncode=0),  # fetch
                MockCompletedProcess(returncode=0, stdout="3\n"),  # commits_ahead
                MockCompletedProcess(returncode=0),  # gh auth status
                MockCompletedProcess(returncode=0, stdout="pushed\n"),  # git push
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),  # current_branch for gh pr create
                MockCompletedProcess(
                    returncode=1,
                    stderr="GraphQL: No commits between main and feature/test"
                ),  # gh pr create fails
                MockCompletedProcess(
                    returncode=0, stdout="git@github.com:owner/repo.git\n"
                ),  # get_repo_info
                MockCompletedProcess(
                    returncode=0,
                    stdout='{"html_url": "https://github.com/owner/repo/pull/55", "number": 55}'
                ),  # gh api
            ]
            result = run_pr_create("Test PR", "Body")
            assert result["success"] is True
            assert result["pr_number"] == 55
            assert result["method_used"] == "gh_api_fallback"
            assert len(result["warnings"]) > 0


class TestPrWorkflowErrorJson:
    """Tests verifying error output is JSON serializable."""

    def test_no_commits_error_is_json_serializable(self):
        """Error for no commits ahead should be JSON serializable."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),
                MockCompletedProcess(returncode=0),
                MockCompletedProcess(returncode=0, stdout="0\n"),
            ]
            with pytest.raises(BbailError) as exc_info:
                run_pr_create("Test", "Body")

            error_dict = exc_info.value.to_dict()
            json_str = json.dumps(error_dict)
            assert isinstance(json_str, str)
            parsed = json.loads(json_str)
            assert parsed["error"]["code"] == PR_NO_COMMITS_AHEAD

    def test_on_main_error_is_json_serializable(self):
        """Error for main branch should be JSON serializable."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="main\n"
            )
            with pytest.raises(BbailError) as exc_info:
                run_pr_create("Test", "Body")

            error_dict = exc_info.value.to_dict()
            json_str = json.dumps(error_dict)
            parsed = json.loads(json_str)
            assert parsed["error"]["code"] == PR_ON_MAIN_BRANCH

    def test_gh_not_auth_error_is_json_serializable(self):
        """Error for gh not authenticated should be JSON serializable."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MockCompletedProcess(returncode=0, stdout="feature/test\n"),
                MockCompletedProcess(returncode=0),
                MockCompletedProcess(returncode=0, stdout="1\n"),
                MockCompletedProcess(returncode=1, stderr="not logged in"),
                MockCompletedProcess(returncode=0, stdout="/usr/bin/gh"),
            ]
            with pytest.raises(BbailError) as exc_info:
                run_pr_create("Test", "Body")

            error_dict = exc_info.value.to_dict()
            json_str = json.dumps(error_dict)
            parsed = json.loads(json_str)
            assert parsed["error"]["code"] == PR_GH_NOT_AUTHENTICATED


class TestCliIntegration:
    """Tests for CLI integration."""

    def test_pr_help(self):
        """bbail pr --help should show help."""
        from aictrl.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main(["pr", "--help"])
        assert exc_info.value.code == 0

    def test_pr_create_requires_title(self):
        """bbail pr create should require --title."""
        from aictrl.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main(["pr", "create"])
        assert exc_info.value.code == 2  # argparse error

    def test_pr_create_with_dry_run(self):
        """bbail pr create --dry-run should check preconditions."""
        from aictrl.cli import main
        with mock.patch("subprocess.run") as mock_run:
            # Return main branch to trigger error
            mock_run.return_value = MockCompletedProcess(
                returncode=0, stdout="main\n"
            )
            exit_code = main(["pr", "create", "--title", "Test", "--dry-run"])
            assert exit_code == 1  # Failure due to being on main
