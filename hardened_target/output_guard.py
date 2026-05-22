import re

from hardened_target.policy import DEFAULT_POLICY, PolicyConfig


SECRET_PATTERNS = [
    r"(?i)\b[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*[^\s]+",
    r"\bsk-[A-Za-z0-9_-]{16,}\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
]

ENV_DUMP_MARKERS = ("OPENAI_API_KEY=", "DATABASE_PASSWORD=", "AWS_SECRET_ACCESS_KEY=", "PRIVATE_KEY=")


def looks_like_secret(text: str) -> bool:
    """Return True when output resembles a secret, API key, or environment dump."""

    if any(marker.lower() in text.lower() for marker in ENV_DUMP_MARKERS):
        return True
    return any(re.search(pattern, text, flags=re.DOTALL) for pattern in SECRET_PATTERNS)


def sanitize_model_output(text: str, policy: PolicyConfig = DEFAULT_POLICY) -> str:
    """Redact secrets and enforce the configured response size limit."""

    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = re.sub(pattern, "[REDACTED_SECRET]", sanitized, flags=re.DOTALL)

    if any(marker.lower() in text.lower() for marker in ENV_DUMP_MARKERS):
        sanitized = (
            "I cannot expose secrets, API keys, credentials, or environment dumps. "
            "Use the audit log to verify that the request was blocked."
        )

    max_chars = max(1, policy.max_response_chars)
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars].rstrip() + "\n[TRUNCATED_BY_OUTPUT_GUARD]"

    return sanitized
