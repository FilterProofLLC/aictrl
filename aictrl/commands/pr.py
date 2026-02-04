"""PR creation workflow for aictrl.

This module provides a canonical PR submission workflow that enforces
preconditions before creating pull requests:
- Must not be on main branch
- Must have commits ahead of origin/main
- Branch must be pushed to origin
- gh CLI must be authenticated

The create_pr function uses a two-tier approach:
1. Try `gh pr create` (standard CLI)
2. On known GraphQL transient errors, fallback to `gh api` (REST API)

Usage:
    aictrl pr create --title "..." --body "..."
"""

import json
import re
from typing import List, Optional, Tuple

from ..util.errors import AICtrlError
from ..util.safe_exec import run_checked


# Error codes for PR operations
PR_ON_MAIN_BRANCH = "AICTRL-5020"
PR_NO_COMMITS_AHEAD = "AICTRL-5021"
PR_GH_NOT_AUTHENTICATED = "AICTRL-5022"
PR_GIT_PUSH_FAILED = "AICTRL-5023"
PR_CREATE_FAILED = "AICTRL-5024"
PR_BOTH_METHODS_FAILED = "AICTRL-5025"

# GraphQL transient error signatures that trigger REST fallback
GRAPHQL_TRANSIENT_ERRORS = [
    "Head sha can't be blank",
    "Base sha can't be blank",
    "No commits between",
    "Head ref must be a branch",
]


def current_branch() -> str:
    """Get the current git branch name.

    Returns:
        Current branch name

    Raises:
        AICtrlError: If not in a git repository or git command fails
    """
    result = run_checked(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        shell=False,
    )
    if result.returncode != 0:
        raise AICtrlError(
            code=PR_CREATE_FAILED,
            message="Failed to get current branch",
            cause=result.stderr.strip() or "Not in a git repository",
            remediation=["Ensure you are in a git repository"],
        )
    return result.stdout.strip()


def commits_ahead_of_main() -> int:
    """Count commits ahead of origin/main.

    Returns:
        Number of commits ahead of origin/main

    Raises:
        AICtrlError: If git command fails
    """
    # First, fetch to ensure we have latest origin/main
    fetch_result = run_checked(
        ["git", "fetch", "origin", "main"],
        shell=False,
    )
    # Fetch failure is not fatal - we may be offline, continue with local state

    result = run_checked(
        ["git", "rev-list", "--count", "origin/main..HEAD"],
        shell=False,
    )
    if result.returncode != 0:
        # Try without origin/ prefix in case remote tracking is not set up
        result = run_checked(
            ["git", "rev-list", "--count", "main..HEAD"],
            shell=False,
        )
        if result.returncode != 0:
            raise AICtrlError(
                code=PR_CREATE_FAILED,
                message="Failed to count commits ahead of main",
                cause=result.stderr.strip(),
                remediation=[
                    "Ensure origin/main exists: git fetch origin main",
                    "Ensure you have commits on your branch",
                ],
            )
    try:
        return int(result.stdout.strip())
    except ValueError:
        return 0


def ensure_gh_auth() -> bool:
    """Check if gh CLI is authenticated.

    Returns:
        True if authenticated

    Raises:
        AICtrlError: If gh is not authenticated or not installed
    """
    result = run_checked(
        ["gh", "auth", "status"],
        shell=False,
    )
    if result.returncode != 0:
        # Check if gh is installed
        which_result = run_checked(
            ["which", "gh"],
            shell=False,
        )
        if which_result.returncode != 0:
            raise AICtrlError(
                code=PR_GH_NOT_AUTHENTICATED,
                message="gh CLI is not installed",
                cause="The gh command was not found",
                remediation=[
                    "Install gh CLI: https://cli.github.com/",
                    "Or use your package manager: apt install gh / brew install gh",
                ],
            )
        raise AICtrlError(
            code=PR_GH_NOT_AUTHENTICATED,
            message="gh CLI is not authenticated",
            cause=result.stderr.strip() or "No GitHub authentication found",
            remediation=[
                "Run: gh auth login",
                "Follow the prompts to authenticate with GitHub",
            ],
        )
    return True


def push_branch(branch: str) -> Tuple[bool, str]:
    """Push current branch to origin.

    Args:
        branch: Branch name to push

    Returns:
        Tuple of (success, output_or_error)

    Raises:
        AICtrlError: If push fails
    """
    result = run_checked(
        ["git", "push", "-u", "origin", branch],
        shell=False,
    )
    if result.returncode != 0:
        raise AICtrlError(
            code=PR_GIT_PUSH_FAILED,
            message="Failed to push branch to origin",
            cause=result.stderr.strip(),
            remediation=[
                "Check your network connection",
                "Ensure you have push access to the repository",
                "Try: git push -u origin HEAD",
            ],
        )
    return True, result.stdout.strip() + result.stderr.strip()


def is_graphql_transient_error(error_text: str) -> bool:
    """Check if an error is a known GraphQL transient error.

    These errors occur when `gh pr create` has timing issues with GitHub's
    GraphQL API, but the REST API typically succeeds.

    Args:
        error_text: The error message to check

    Returns:
        True if the error matches a known transient pattern
    """
    error_lower = error_text.lower()
    for pattern in GRAPHQL_TRANSIENT_ERRORS:
        if pattern.lower() in error_lower:
            return True
    return False


def get_repo_info() -> Tuple[str, str]:
    """Get the owner and repo name from the git remote.

    Returns:
        Tuple of (owner, repo)

    Raises:
        AICtrlError: If unable to determine repo info
    """
    result = run_checked(
        ["git", "remote", "get-url", "origin"],
        shell=False,
    )
    if result.returncode != 0:
        raise AICtrlError(
            code=PR_CREATE_FAILED,
            message="Failed to get remote URL",
            cause=result.stderr.strip() or "No origin remote configured",
            remediation=["Ensure you have a git remote named 'origin'"],
        )

    url = result.stdout.strip()

    # Parse owner/repo from various URL formats:
    # git@github.com:owner/repo.git
    # https://github.com/owner/repo.git
    # https://github.com/owner/repo
    match = re.search(r"[:/]([^/]+)/([^/]+?)(?:\.git)?$", url)
    if not match:
        raise AICtrlError(
            code=PR_CREATE_FAILED,
            message="Failed to parse repository from remote URL",
            cause=f"Could not extract owner/repo from: {url}",
            remediation=["Ensure origin points to a GitHub repository"],
        )

    return match.group(1), match.group(2)


def create_pr_via_api(
    title: str, body: str, head: str, base: str = "main"
) -> dict:
    """Create a pull request using the GitHub REST API via gh api.

    This is used as a fallback when `gh pr create` fails with GraphQL errors.

    Args:
        title: PR title
        body: PR body/description
        head: Head branch name
        base: Base branch (default: main)

    Returns:
        Dict with PR details

    Raises:
        AICtrlError: If PR creation fails
    """
    owner, repo = get_repo_info()

    result = run_checked(
        [
            "gh", "api",
            f"repos/{owner}/{repo}/pulls",
            "--method", "POST",
            "-f", f"title={title}",
            "-f", f"body={body}",
            "-f", f"head={head}",
            "-f", f"base={base}",
        ],
        shell=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Check for common error patterns
        if "already exists" in stderr.lower():
            raise AICtrlError(
                code=PR_CREATE_FAILED,
                message="A pull request already exists for this branch",
                cause=stderr,
                remediation=[
                    "Use gh pr view to see the existing PR",
                    "Or close the existing PR first",
                ],
            )
        raise AICtrlError(
            code=PR_CREATE_FAILED,
            message="Failed to create pull request via REST API",
            cause=stderr,
            remediation=[
                "Check gh auth status",
                "Ensure the branch is pushed to origin",
                "Check GitHub API status",
            ],
        )

    # Parse the JSON response
    try:
        pr_data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise AICtrlError(
            code=PR_CREATE_FAILED,
            message="Failed to parse API response",
            cause=str(e),
            remediation=["This may be a transient GitHub API error"],
        )

    return {
        "success": True,
        "method_used": "gh_api_fallback",
        "pr_url": pr_data.get("html_url", ""),
        "pr_number": pr_data.get("number"),
        "title": title,
        "base": base,
        "head": head,
        "warnings": ["Used REST API fallback due to GraphQL transient error"],
    }


def create_pr(title: str, body: str, base: str = "main") -> dict:
    """Create a pull request using gh CLI with REST API fallback.

    This function implements a two-tier approach:
    1. Try `gh pr create` (standard GraphQL-based CLI)
    2. On known GraphQL transient errors, fallback to `gh api` (REST API)

    Args:
        title: PR title
        body: PR body/description
        base: Base branch (default: main)

    Returns:
        Dict with PR details including:
        - success: bool
        - method_used: "gh_pr_create" or "gh_api_fallback"
        - pr_url: URL of created PR
        - pr_number: PR number
        - title, base, head: PR metadata
        - warnings: list of any warnings

    Raises:
        AICtrlError: If PR creation fails with both methods
    """
    branch = current_branch()
    warnings: List[str] = []
    gh_pr_create_error = None

    # Step 1: Try gh pr create
    result = run_checked(
        [
            "gh", "pr", "create",
            "-B", base,
            "-H", branch,
            "--title", title,
            "--body", body,
        ],
        shell=False,
    )

    if result.returncode == 0:
        # Success with gh pr create
        pr_url = result.stdout.strip()
        pr_number = None
        if "/pull/" in pr_url:
            try:
                pr_number = int(pr_url.split("/pull/")[-1].split("/")[0])
            except (ValueError, IndexError):
                pass

        return {
            "success": True,
            "method_used": "gh_pr_create",
            "pr_url": pr_url,
            "pr_number": pr_number,
            "title": title,
            "base": base,
            "head": branch,
            "warnings": warnings,
        }

    # Step 2: Check if this is a transient GraphQL error
    stderr = result.stderr.strip()

    # Check for "already exists" - this is not transient, fail immediately
    if "already exists" in stderr.lower():
        raise AICtrlError(
            code=PR_CREATE_FAILED,
            message="A pull request already exists for this branch",
            cause=stderr,
            remediation=[
                "Use gh pr view to see the existing PR",
                "Or close the existing PR first",
            ],
        )

    # Check if this is a known GraphQL transient error
    if is_graphql_transient_error(stderr):
        gh_pr_create_error = stderr
        # Step 3: Try REST API fallback
        try:
            return create_pr_via_api(title, body, branch, base)
        except AICtrlError as api_error:
            # Both methods failed
            raise AICtrlError(
                code=PR_BOTH_METHODS_FAILED,
                message="PR creation failed with both gh pr create and REST API",
                cause=f"gh pr create: {gh_pr_create_error}\ngh api: {api_error.cause}",
                remediation=[
                    "Check gh auth status",
                    "Ensure the branch is pushed to origin",
                    "Try: gh pr create --web",
                    "Check GitHub status page for API issues",
                ],
            )

    # Not a transient error, fail with original error
    raise AICtrlError(
        code=PR_CREATE_FAILED,
        message="Failed to create pull request",
        cause=stderr,
        remediation=[
            "Check gh auth status",
            "Ensure the branch is pushed to origin",
            "Try: gh pr create --web",
        ],
    )


def run_pr_create(title: str, body: str, base: str = "main", dry_run: bool = False) -> dict:
    """Run the full PR creation workflow.

    This is the main entry point that enforces all preconditions:
    1. Not on main branch
    2. Has commits ahead of origin/main
    3. gh is authenticated
    4. Push branch to origin
    5. Create PR

    Args:
        title: PR title
        body: PR body/description
        base: Base branch (default: main)
        dry_run: If True, only check preconditions without creating PR

    Returns:
        Dict with workflow result

    Raises:
        AICtrlError: If any precondition fails or PR creation fails
    """
    result = {
        "checks": [],
        "success": False,
    }

    # Check 1: Not on main branch
    branch = current_branch()
    if branch == "main" or branch == "master":
        raise AICtrlError(
            code=PR_ON_MAIN_BRANCH,
            message=f"Cannot create PR from {branch} branch",
            cause="PRs must be created from a feature branch, not main/master",
            remediation=[
                "Create a feature branch: git checkout -b feature/my-feature",
                "Make your changes and commit",
                "Then run: python3 -m bbail pr create",
            ],
        )
    result["checks"].append({"name": "branch_check", "status": "pass", "branch": branch})

    # Check 2: Has commits ahead of main
    ahead = commits_ahead_of_main()
    if ahead == 0:
        raise AICtrlError(
            code=PR_NO_COMMITS_AHEAD,
            message="No commits ahead of origin/main",
            cause="Your branch has no new commits to include in a PR",
            remediation=[
                "Make changes and commit: git add . && git commit -m 'message'",
                "Ensure you're on the correct branch: git branch",
                "Check commit history: git log --oneline origin/main..HEAD",
            ],
        )
    result["checks"].append({"name": "commits_ahead", "status": "pass", "count": ahead})

    # Check 3: gh is authenticated
    ensure_gh_auth()
    result["checks"].append({"name": "gh_auth", "status": "pass"})

    if dry_run:
        result["success"] = True
        result["dry_run"] = True
        result["method_used"] = None
        result["warnings"] = []
        result["message"] = "All preconditions passed (dry run - no PR created)"
        return result

    # Step 4: Push branch to origin
    push_success, push_output = push_branch(branch)
    result["checks"].append({"name": "push", "status": "pass", "output": push_output})

    # Step 5: Create PR
    pr_result = create_pr(title, body, base)
    result.update(pr_result)

    return result
