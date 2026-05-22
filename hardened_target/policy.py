from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from hardened_target.config import PROJECT_ROOT, settings


@dataclass(frozen=True)
class PolicyDecision:
    """Readable policy decision returned by the hardened controls."""

    allowed: bool
    reason: str


@dataclass(frozen=True)
class PolicyConfig:
    """Simple defensive rules for the educational hardened target."""

    allowed_file_paths: tuple[Path, ...] = field(
        default_factory=lambda: (
            PROJECT_ROOT / "hardened_target" / "knowledge_base",
            PROJECT_ROOT / "README.md",
        )
    )
    blocked_file_patterns: tuple[str, ...] = (
        ".env",
        "*.env",
        "*.env.*",
        "*credential*",
        "*credentials*",
        "*creds*",
        "*secret*",
        "*.pem",
        "*.key",
        "id_rsa",
        "id_dsa",
        "id_ed25519",
        "/etc/passwd",
        "/etc/shadow",
        "database_creds.txt",
    )
    allowed_email_domains: tuple[str, ...] = ("agentsploit.local", "example.org")
    require_confirmation_for_sensitive_actions: bool = True
    max_tool_calls_per_request: int = settings.max_tool_calls_per_request
    max_response_chars: int = settings.max_response_chars


DEFAULT_POLICY = PolicyConfig()


def resolve_requested_path(filepath: str) -> Path:
    """Resolve a user-supplied path relative to the project root."""

    requested_path = Path(filepath).expanduser()
    if not requested_path.is_absolute():
        requested_path = PROJECT_ROOT / requested_path
    return requested_path.resolve(strict=False)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def matches_blocked_file_pattern(path: Path, policy: PolicyConfig = DEFAULT_POLICY) -> bool:
    """Return True when a path resembles a secret or sensitive system file."""

    normalized = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    for pattern in policy.blocked_file_patterns:
        lowered = pattern.lower()
        if fnmatch(name, lowered) or fnmatch(normalized, lowered):
            return True
        if lowered.startswith("/") and normalized == lowered:
            return True
    return False


def is_file_read_allowed(filepath: str, policy: PolicyConfig = DEFAULT_POLICY) -> PolicyDecision:
    """Allow local file reads only inside explicitly allowed directories or files."""

    if not filepath.strip():
        return PolicyDecision(False, "empty filepath")

    requested_path = resolve_requested_path(filepath)
    if matches_blocked_file_pattern(requested_path, policy):
        return PolicyDecision(False, "blocked sensitive file pattern")

    for allowed_path in policy.allowed_file_paths:
        allowed_path = allowed_path.resolve(strict=False)
        if requested_path == allowed_path or _is_within(requested_path, allowed_path):
            return PolicyDecision(True, "path is explicitly allowlisted")

    return PolicyDecision(False, "path is outside the file allowlist")


def is_email_allowed(to: str, policy: PolicyConfig = DEFAULT_POLICY) -> PolicyDecision:
    """Allow email only to explicitly trusted domains."""

    address = to.strip().lower()
    if "@" not in address:
        return PolicyDecision(False, "recipient is not a valid email address")

    domain = address.rsplit("@", 1)[1]
    if domain in {item.lower() for item in policy.allowed_email_domains}:
        return PolicyDecision(True, "email domain is allowlisted")

    return PolicyDecision(False, "email domain is not allowlisted")


def is_sensitive_action_confirmed(
    tool_name: str,
    arguments: dict[str, Any],
    policy: PolicyConfig = DEFAULT_POLICY,
) -> PolicyDecision:
    """Require explicit confirmation metadata for sensitive write-capable tools."""

    if not policy.require_confirmation_for_sensitive_actions:
        return PolicyDecision(True, "confirmation not required by policy")
    if tool_name != "send_email":
        return PolicyDecision(True, "tool is not confirmation-gated")
    if bool(arguments.get("confirmed")):
        return PolicyDecision(True, "sensitive action was explicitly confirmed")
    return PolicyDecision(False, "sensitive action requires explicit confirmation")
