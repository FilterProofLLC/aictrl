"""Error codes and exit status handling for aictrl.

Error code ranges per docs/spec/v1.md:
- AICTRL-0xxx: General errors
- AICTRL-1xxx: System errors
- AICTRL-2xxx: GPU errors
- AICTRL-3xxx: Network errors
- AICTRL-4xxx: AI/Container errors
- AICTRL-5xxx: AI interface errors

Note: Legacy BBAIL-xxxx codes are preserved for backward compatibility.
"""

# Exit codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2

# Error code constants
class ErrorCodes:
    """AICtrl error codes."""

    # General errors (0xxx)
    UNKNOWN_COMMAND = "AICTRL-0001"
    INVALID_ARGUMENT = "AICTRL-0002"
    PERMISSION_DENIED = "AICTRL-0003"
    OPERATION_CANCELLED = "AICTRL-0004"

    # System errors (1xxx)
    BOOT_HEALTH_FAILED = "AICTRL-1001"
    FILESYSTEM_ERROR = "AICTRL-1002"
    SERVICE_NOT_RUNNING = "AICTRL-1003"
    UPDATE_CHECK_FAILED = "AICTRL-1004"
    ROLLBACK_FAILED = "AICTRL-1005"

    # GPU errors (2xxx)
    NO_GPU_DETECTED = "AICTRL-2001"
    DRIVER_NOT_INSTALLED = "AICTRL-2002"
    DRIVER_VERSION_MISMATCH = "AICTRL-2003"
    GPU_MEMORY_ERROR = "AICTRL-2004"
    GPU_TEMP_CRITICAL = "AICTRL-2005"
    CONTAINER_GPU_ACCESS_FAILED = "AICTRL-2006"

    # Network errors (3xxx)
    NO_NETWORK = "AICTRL-3001"
    DNS_FAILED = "AICTRL-3002"
    SSH_CONFIG_ERROR = "AICTRL-3003"
    FIREWALL_ERROR = "AICTRL-3004"
    TAILSCALE_FAILED = "AICTRL-3005"

    # AI/Container errors (4xxx)
    CONTAINER_RUNTIME_UNAVAILABLE = "AICTRL-4001"
    IMAGE_PULL_FAILED = "AICTRL-4002"
    CONTAINER_START_FAILED = "AICTRL-4003"
    MODEL_ENDPOINT_UNAVAILABLE = "AICTRL-4004"

    # AI interface errors (5xxx)
    AI_BACKEND_NOT_CONFIGURED = "AICTRL-5001"
    AI_BACKEND_UNREACHABLE = "AICTRL-5002"
    AI_REQUEST_TIMEOUT = "AICTRL-5003"
    AI_RESPONSE_INVALID = "AICTRL-5004"
    AI_AUDIT_LOG_FAILED = "AICTRL-5005"
    HOST_SAFETY_VIOLATION = "AICTRL-5010"
    HOST_SAFETY_OVERRIDE_INCOMPLETE = "AICTRL-5011"

    # PR workflow errors (502x)
    PR_ON_MAIN_BRANCH = "AICTRL-5020"
    PR_NO_COMMITS_AHEAD = "AICTRL-5021"
    PR_GH_NOT_AUTHENTICATED = "AICTRL-5022"
    PR_GIT_PUSH_FAILED = "AICTRL-5023"
    PR_CREATE_FAILED = "AICTRL-5024"


class AICtrlError(Exception):
    """Base exception for aictrl errors."""

    def __init__(self, code: str, message: str, cause: str = None, remediation: list = None):
        self.code = code
        self.message = message
        self.cause = cause
        self.remediation = remediation or []
        super().__init__(message)

    def to_dict(self) -> dict:
        """Return error as dictionary for JSON output."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "cause": self.cause,
                "remediation": self.remediation,
            }
        }


# Backward compatibility alias
BbailError = AICtrlError
