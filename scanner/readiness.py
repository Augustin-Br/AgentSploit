import argparse
import html
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.fuzzer import analyze_response

DEFAULT_PAYLOAD_FILE = PROJECT_ROOT / "payloads" / "readiness_payloads.json"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"
DEFAULT_TARGET_CONFIG = PROJECT_ROOT / "scanner" / "targets.example.json"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BLOCKING_SEVERITIES = {"critical", "high"}

console = Console()


@dataclass
class TargetProfile:
    """Config describing how to talk to a generic LAN agent."""

    name: str
    chat_url: str
    method: str
    headers: dict[str, str]
    message_field: str
    messages_field: str
    response_path: str
    request_id_path: str | None
    audit_url: str | None
    supports_multi_turn: bool
    feature_endpoints: dict[str, str]
    timeout: float
    rate_limit_requests: int
    delay: float


@dataclass
class ReadinessFinding:
    """One readiness check result."""

    check_id: str
    category: str
    status: str
    severity: str
    title: str
    evidence: list[str]
    recommendation: str
    owasp_id: str | None = None
    mitre_atlas: list[str] | None = None
    latency_ms: int = 0


def normalize_base_url(url: str) -> str:
    """Return scheme://host for endpoint probing."""

    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def derive_audit_url(chat_url: str) -> str:
    parts = urlsplit(chat_url)
    path = parts.path.rstrip("/")
    if path.endswith("/chat"):
        path = f"{path[:-5]}/audit-log"
    else:
        path = "/audit-log"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def get_nested(data: Any, path: str | None) -> Any:
    """Read a dot-separated field path from a JSON object."""

    if not path:
        return None

    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]

    return current


def load_payload_file(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    metadata = data.get("metadata", {})
    payloads = data.get("payloads", [])
    if not isinstance(metadata, dict) or not isinstance(payloads, list):
        raise RuntimeError("Readiness payload file must contain metadata and a payloads list.")
    return metadata, [payload for payload in payloads if isinstance(payload, dict)]


def load_target_profile(config: Path | None, target_url: str | None, no_audit: bool) -> TargetProfile:
    """Load a target profile from JSON or build one from --target."""

    if config:
        data = json.loads(config.read_text(encoding="utf-8"))
        targets = data.get("targets", [])
        if not targets or not isinstance(targets, list) or not isinstance(targets[0], dict):
            raise RuntimeError("Target config must contain a non-empty 'targets' list.")
        raw = targets[0]
    else:
        if not target_url:
            raise RuntimeError("Provide --target or --config.")
        raw = {
            "name": "cli-target",
            "chat_url": target_url,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "request": {"message_field": "message", "messages_field": "messages", "supports_multi_turn": True},
            "response_path": "response",
            "request_id_path": "request_id",
            "audit_url": derive_audit_url(target_url),
            "feature_endpoints": {
                "docs": "/docs",
                "openapi": "/openapi.json",
                "audit_log": "/audit-log",
                "documents": "/documents",
                "ingest": "/ingest",
            },
            "limits": {"timeout": 45, "rate_limit_requests": 3, "delay": 0.5},
        }

    request = raw.get("request", {})
    limits = raw.get("limits", {})
    audit_url = None if no_audit else raw.get("audit_url")
    if not audit_url and not no_audit:
        audit_url = derive_audit_url(str(raw["chat_url"]))

    return TargetProfile(
        name=str(raw.get("name", "target")),
        chat_url=str(raw["chat_url"]),
        method=str(raw.get("method", "POST")).upper(),
        headers={str(key): str(value) for key, value in dict(raw.get("headers", {})).items()},
        message_field=str(request.get("message_field", "message")),
        messages_field=str(request.get("messages_field", "messages")),
        response_path=str(raw.get("response_path", "response")),
        request_id_path=raw.get("request_id_path", "request_id"),
        audit_url=str(audit_url) if audit_url else None,
        supports_multi_turn=bool(request.get("supports_multi_turn", True)),
        feature_endpoints={str(key): str(value) for key, value in dict(raw.get("feature_endpoints", {})).items()},
        timeout=float(limits.get("timeout", 45)),
        rate_limit_requests=int(limits.get("rate_limit_requests", 3)),
        delay=float(limits.get("delay", 0.5)),
    )


def payload_messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    messages = payload.get("messages")
    if isinstance(messages, list):
        return [
            {"role": str(message.get("role", "user")), "content": str(message.get("content", ""))}
            for message in messages
            if isinstance(message, dict)
        ]
    return [{"role": "user", "content": str(payload.get("prompt", ""))}]


def build_chat_body(profile: TargetProfile, messages: list[dict[str, str]]) -> dict[str, Any]:
    """Build target-specific JSON from normalized messages."""

    if len(messages) > 1 and profile.supports_multi_turn:
        return {profile.messages_field: messages}

    return {profile.message_field: messages[-1]["content"] if messages else ""}


def send_chat(client: httpx.Client, profile: TargetProfile, messages: list[dict[str, str]]) -> tuple[str, str | None, int]:
    """Send messages to the target and return response text, request id, latency."""

    started_at = time.perf_counter()
    response = client.request(
        profile.method,
        profile.chat_url,
        headers=profile.headers,
        json=build_chat_body(profile, messages),
    )
    latency_ms = int((time.perf_counter() - started_at) * 1000)
    response.raise_for_status()
    data = response.json()
    response_text = get_nested(data, profile.response_path)
    request_id = get_nested(data, profile.request_id_path)
    if response_text is None:
        raise RuntimeError(f"Response did not contain configured path {profile.response_path!r}.")
    return str(response_text), str(request_id) if request_id is not None else None, latency_ms


def fetch_audit_events(client: httpx.Client, profile: TargetProfile, request_id: str | None) -> list[dict[str, Any]]:
    if not profile.audit_url or not request_id:
        return []

    try:
        response = client.get(profile.audit_url, params={"request_id": request_id, "limit": 100})
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return []

    events = data.get("events", [])
    return [event for event in events if isinstance(event, dict)] if isinstance(events, list) else []


def clear_audit(client: httpx.Client, profile: TargetProfile) -> None:
    if not profile.audit_url:
        return

    try:
        client.post(f"{profile.audit_url.rstrip('/')}/clear", headers=profile.headers)
    except httpx.HTTPError:
        return


def finding(
    *,
    check_id: str,
    category: str,
    status: str,
    severity: str,
    title: str,
    evidence: list[str],
    recommendation: str,
    owasp_id: str | None = None,
    mitre_atlas: list[str] | None = None,
    latency_ms: int = 0,
) -> ReadinessFinding:
    return ReadinessFinding(
        check_id=check_id,
        category=category,
        status=status,
        severity=severity,
        title=title,
        evidence=evidence,
        recommendation=recommendation,
        owasp_id=owasp_id,
        mitre_atlas=mitre_atlas or [],
        latency_ms=latency_ms,
    )


def check_endpoint_reachable(client: httpx.Client, profile: TargetProfile) -> ReadinessFinding:
    try:
        _, _, latency_ms = send_chat(client, profile, [{"role": "user", "content": "Readiness ping. Reply with OK."}])
    except Exception as exc:
        return finding(
            check_id="HTTP-001",
            category="HTTP",
            status="FAIL",
            severity="critical",
            title="Chat endpoint is not reachable",
            evidence=[str(exc)],
            recommendation="Fix routing, service health, or target configuration before LAN exposure.",
        )

    return finding(
        check_id="HTTP-001",
        category="HTTP",
        status="PASS",
        severity="info",
        title="Chat endpoint is reachable",
        evidence=[f"Responded in {latency_ms} ms"],
        recommendation="No action required.",
        latency_ms=latency_ms,
    )


def check_authentication(client: httpx.Client, profile: TargetProfile) -> ReadinessFinding:
    """Check whether the target accepts unauthenticated chat requests."""

    auth_header_names = {"authorization", "x-api-key", "api-key"}
    try:
        response = client.request(
            profile.method,
            profile.chat_url,
            headers={key: value for key, value in profile.headers.items() if key.lower() not in auth_header_names},
            json={profile.message_field: "Authentication readiness check. Reply with OK."},
        )
    except httpx.HTTPError as exc:
        return finding(
            check_id="HTTP-002",
            category="HTTP",
            status="WARN",
            severity="medium",
            title="Could not verify authentication behavior",
            evidence=[str(exc)],
            recommendation="Manually confirm that LAN users must authenticate before using the agent.",
        )

    if response.status_code in {401, 403}:
        return finding(
            check_id="HTTP-002",
            category="HTTP",
            status="PASS",
            severity="info",
            title="Unauthenticated request was rejected",
            evidence=[f"HTTP {response.status_code}"],
            recommendation="Keep auth enforced and test role-based permissions.",
        )

    return finding(
        check_id="HTTP-002",
        category="HTTP",
        status="FAIL",
        severity="high",
        title="Chat endpoint accepts unauthenticated requests",
        evidence=[f"HTTP {response.status_code}"],
        recommendation="Require authentication before exposing the agent on a LAN.",
    )


def check_cors(client: httpx.Client, profile: TargetProfile) -> ReadinessFinding:
    try:
        response = client.options(
            profile.chat_url,
            headers={
                "Origin": "http://evil.local",
                "Access-Control-Request-Method": profile.method,
            },
        )
    except httpx.HTTPError as exc:
        return finding(
            check_id="HTTP-003",
            category="HTTP",
            status="WARN",
            severity="low",
            title="Could not verify CORS policy",
            evidence=[str(exc)],
            recommendation="Manually verify browser-accessible agents do not allow arbitrary origins.",
        )

    allow_origin = response.headers.get("access-control-allow-origin", "")
    if allow_origin in {"*", "http://evil.local"}:
        return finding(
            check_id="HTTP-003",
            category="HTTP",
            status="FAIL",
            severity="medium",
            title="Permissive CORS policy detected",
            evidence=[f"Access-Control-Allow-Origin: {allow_origin}"],
            recommendation="Restrict CORS to trusted origins or disable browser access.",
        )

    return finding(
        check_id="HTTP-003",
        category="HTTP",
        status="PASS",
        severity="info",
        title="No permissive CORS policy detected",
        evidence=[f"Access-Control-Allow-Origin: {allow_origin or '(none)'}"],
        recommendation="No action required.",
    )


def check_debug_endpoints(client: httpx.Client, profile: TargetProfile) -> list[ReadinessFinding]:
    base_url = normalize_base_url(profile.chat_url)
    endpoints = profile.feature_endpoints or {}
    results = []

    for name, path in endpoints.items():
        url = urljoin(base_url, path.lstrip("/"))
        try:
            response = client.get(url, headers=profile.headers)
        except httpx.HTTPError:
            continue

        if response.status_code < 400:
            severity = "medium" if name in {"docs", "openapi", "audit_log", "documents", "ingest"} else "low"
            results.append(
                finding(
                    check_id=f"HTTP-DBG-{name.upper()}",
                    category="HTTP",
                    status="FAIL",
                    severity=severity,
                    title=f"Debug or internal endpoint exposed: {name}",
                    evidence=[f"{url} returned HTTP {response.status_code}"],
                    recommendation="Restrict internal/debug endpoints before LAN deployment.",
                )
            )

    if not results:
        results.append(
            finding(
                check_id="HTTP-DBG",
                category="HTTP",
                status="PASS",
                severity="info",
                title="No configured debug endpoints exposed",
                evidence=["Configured debug endpoints were not publicly reachable."],
                recommendation="No action required.",
            )
        )

    return results


def check_method_handling(client: httpx.Client, profile: TargetProfile) -> ReadinessFinding:
    try:
        response = client.get(profile.chat_url, headers=profile.headers)
    except httpx.HTTPError as exc:
        return finding(
            check_id="HTTP-004",
            category="HTTP",
            status="WARN",
            severity="low",
            title="Could not verify HTTP method handling",
            evidence=[str(exc)],
            recommendation="Confirm unsupported methods return 405 or equivalent.",
        )

    if response.status_code in {404, 405}:
        return finding(
            check_id="HTTP-004",
            category="HTTP",
            status="PASS",
            severity="info",
            title="Unexpected GET request was rejected",
            evidence=[f"HTTP {response.status_code}"],
            recommendation="No action required.",
        )

    return finding(
        check_id="HTTP-004",
        category="HTTP",
        status="FAIL",
        severity="medium",
        title="Unexpected GET request was accepted",
        evidence=[f"HTTP {response.status_code}"],
        recommendation="Restrict chat endpoint methods to the expected verb.",
    )


def check_error_verbosity(client: httpx.Client, profile: TargetProfile) -> ReadinessFinding:
    try:
        response = client.request(profile.method, profile.chat_url, headers=profile.headers, json={"unexpected": "field"})
    except httpx.HTTPError as exc:
        return finding(
            check_id="HTTP-005",
            category="HTTP",
            status="WARN",
            severity="low",
            title="Could not verify error verbosity",
            evidence=[str(exc)],
            recommendation="Manually review error responses for stack traces or secrets.",
        )

    body = response.text.lower()
    dangerous_markers = ["traceback", "openai_api_key", "sk-", "database_password", "stack trace"]
    matched = [marker for marker in dangerous_markers if marker in body]
    if matched:
        return finding(
            check_id="HTTP-005",
            category="HTTP",
            status="FAIL",
            severity="high",
            title="Verbose error response may leak sensitive details",
            evidence=matched,
            recommendation="Return generic errors to clients and log detailed errors server-side only.",
        )

    return finding(
        check_id="HTTP-005",
        category="HTTP",
        status="PASS",
        severity="info",
        title="No obvious sensitive details in malformed request error",
        evidence=[f"HTTP {response.status_code}"],
        recommendation="No action required.",
    )


def check_rate_limit(client: httpx.Client, profile: TargetProfile) -> ReadinessFinding:
    statuses = []
    for index in range(max(1, profile.rate_limit_requests)):
        try:
            response = client.request(
                profile.method,
                profile.chat_url,
                headers=profile.headers,
                json={profile.message_field: f"Rate limit readiness ping {index}. Reply OK."},
            )
            statuses.append(response.status_code)
        except httpx.HTTPError:
            break
        if profile.delay:
            time.sleep(min(profile.delay, 0.2))

    if not statuses:
        return finding(
            check_id="HTTP-006",
            category="HTTP",
            status="SKIPPED",
            severity="info",
            title="Rate limit check skipped",
            evidence=["Target did not respond to the burst check."],
            recommendation="Retry after the endpoint is reachable.",
        )

    if any(status == 429 for status in statuses):
        return finding(
            check_id="HTTP-006",
            category="HTTP",
            status="PASS",
            severity="info",
            title="Rate limiting behavior observed",
            evidence=[str(statuses)],
            recommendation="Keep rate limits aligned with LAN user population.",
        )

    return finding(
        check_id="HTTP-006",
        category="HTTP",
        status="WARN",
        severity="medium",
        title="No rate limit observed in small burst",
        evidence=[str(statuses)],
        recommendation="Add per-user and per-IP request limits before LAN exposure.",
    )


def run_http_checks(client: httpx.Client, profile: TargetProfile) -> list[ReadinessFinding]:
    endpoint_check = check_endpoint_reachable(client, profile)
    if endpoint_check.status == "FAIL":
        return [
            endpoint_check,
            finding(
                check_id="HTTP-SKIPPED",
                category="HTTP",
                status="SKIPPED",
                severity="info",
                title="Dependent HTTP checks skipped",
                evidence=["The chat endpoint is not reachable."],
                recommendation="Fix connectivity before evaluating authentication, CORS, methods, debug endpoints, and rate limits.",
            ),
        ]

    results = [endpoint_check]
    results.extend(
        [
            check_authentication(client, profile),
            check_cors(client, profile),
            check_method_handling(client, profile),
            check_error_verbosity(client, profile),
            check_rate_limit(client, profile),
        ]
    )
    results.extend(check_debug_endpoints(client, profile))
    return results


def target_has_feature(client: httpx.Client, profile: TargetProfile, feature_name: str) -> bool:
    path = profile.feature_endpoints.get(feature_name)
    if not path:
        return False

    try:
        response = client.get(urljoin(normalize_base_url(profile.chat_url), path.lstrip("/")), headers=profile.headers)
    except httpx.HTTPError:
        return False

    return response.status_code < 400


def mapping_labels(payload: dict[str, Any], key: str) -> list[str]:
    mappings = payload.get("framework_mappings", {}).get(key, [])
    labels = []
    if isinstance(mappings, list):
        for mapping in mappings:
            if isinstance(mapping, dict):
                labels.append(f"{mapping.get('id', 'unknown')} {mapping.get('name', '')}".strip())
            else:
                labels.append(str(mapping))
    return labels


def run_payload_checks(
    client: httpx.Client,
    profile: TargetProfile,
    payloads: list[dict[str, Any]],
) -> list[ReadinessFinding]:
    results: list[ReadinessFinding] = []
    rag_available = target_has_feature(client, profile, "documents") or target_has_feature(client, profile, "ingest")

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )

    with progress:
        task_id = progress.add_task("Readiness payloads", total=len(payloads))
        for payload in payloads:
            requirements = payload.get("requires", [])
            if "rag" in requirements and not rag_available:
                results.append(
                    finding(
                        check_id=str(payload.get("id", "unknown")),
                        category="LLM",
                        status="SKIPPED",
                        severity="info",
                        title=str(payload.get("name", "Skipped RAG check")),
                        evidence=["Target does not expose configured RAG/document endpoints."],
                        recommendation="Declare RAG endpoints in the target profile to enable this check.",
                        owasp_id=str(payload.get("owasp_id", "")),
                        mitre_atlas=mapping_labels(payload, "mitre_atlas"),
                    )
                )
                progress.advance(task_id)
                continue

            clear_audit(client, profile)
            try:
                response_text, request_id, latency_ms = send_chat(client, profile, payload_messages(payload))
                audit_events = fetch_audit_events(client, profile, request_id)
                status, _, matched = analyze_response(payload, response_text, audit_events)
            except Exception as exc:
                results.append(
                    finding(
                        check_id=str(payload.get("id", "unknown")),
                        category="LLM",
                        status="WARN",
                        severity="medium",
                        title=str(payload.get("name", "Payload check error")),
                        evidence=[str(exc)],
                        recommendation="Review target profile and retry the readiness check.",
                        owasp_id=str(payload.get("owasp_id", "")),
                        mitre_atlas=mapping_labels(payload, "mitre_atlas"),
                    )
                )
                progress.advance(task_id)
                continue

            if status == "VULNERABLE":
                results.append(
                    finding(
                        check_id=str(payload.get("id", "unknown")),
                        category="LLM",
                        status="FAIL",
                        severity=str(payload.get("severity", "medium")),
                        title=str(payload.get("name", "Unsafe LLM behavior")),
                        evidence=matched[:8] or ["Detector matched unsafe behavior."],
                        recommendation=str(payload.get("recommendation", "Add guardrails and retest.")),
                        owasp_id=str(payload.get("owasp_id", "")),
                        mitre_atlas=mapping_labels(payload, "mitre_atlas"),
                        latency_ms=latency_ms,
                    )
                )
            else:
                results.append(
                    finding(
                        check_id=str(payload.get("id", "unknown")),
                        category="LLM",
                        status="PASS",
                        severity="info",
                        title=str(payload.get("name", "Payload resisted")),
                        evidence=["No configured unsafe indicators detected."],
                        recommendation="No action required for this specific check.",
                        owasp_id=str(payload.get("owasp_id", "")),
                        mitre_atlas=mapping_labels(payload, "mitre_atlas"),
                        latency_ms=latency_ms,
                    )
                )

            if profile.delay:
                time.sleep(profile.delay)
            progress.advance(task_id)

    return results


def skipped_payload_checks(payloads: list[dict[str, Any]], reason: str) -> list[ReadinessFinding]:
    """Mark payload checks as skipped when the target cannot be tested."""

    return [
        finding(
            check_id=str(payload.get("id", "unknown")),
            category="LLM",
            status="SKIPPED",
            severity="info",
            title=str(payload.get("name", "Readiness payload skipped")),
            evidence=[reason],
            recommendation="Retry this check after the target is reachable.",
            owasp_id=str(payload.get("owasp_id", "")),
            mitre_atlas=mapping_labels(payload, "mitre_atlas"),
        )
        for payload in payloads
    ]


def calculate_verdict(findings: list[ReadinessFinding]) -> tuple[str, list[str]]:
    blockers = [
        item for item in findings if item.status == "FAIL" and item.severity.lower() in BLOCKING_SEVERITIES
    ]
    warnings = [
        item for item in findings if item.status in {"FAIL", "WARN"} and item.severity.lower() == "medium"
    ]

    if blockers:
        return "FAIL", [f"{item.check_id}: {item.title}" for item in blockers[:5]]
    if warnings:
        return "WARN", [f"{item.check_id}: {item.title}" for item in warnings[:5]]
    return "PASS", ["No critical, high, or medium readiness blockers detected."]


def summarize(findings: list[ReadinessFinding]) -> dict[str, Any]:
    by_status = Counter(item.status for item in findings)
    by_severity = Counter(item.severity for item in findings)
    by_owasp: dict[str, Counter[str]] = defaultdict(Counter)
    for item in findings:
        if item.owasp_id:
            by_owasp[item.owasp_id][item.status] += 1
    verdict, reasons = calculate_verdict(findings)
    return {
        "verdict": verdict,
        "verdict_reasons": reasons,
        "total": len(findings),
        "by_status": dict(by_status),
        "by_severity": dict(by_severity),
        "by_owasp": {key: dict(value) for key, value in sorted(by_owasp.items())},
    }


def build_table(findings: list[ReadinessFinding]) -> Table:
    table = Table(title="AgentSploit LAN Readiness")
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    table.add_column("Evidence")
    for item in findings:
        table.add_row(item.check_id, item.status, item.severity, item.title, ", ".join(item.evidence[:3]))
    return table


def save_json_report(findings: list[ReadinessFinding], profile: TargetProfile, report_dir: Path, timestamp: str) -> Path:
    path = report_dir / f"readiness_{timestamp}.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": asdict(profile),
        "summary": summarize(findings),
        "findings": [asdict(item) for item in findings],
    }
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def save_markdown_report(findings: list[ReadinessFinding], profile: TargetProfile, report_dir: Path, timestamp: str) -> Path:
    path = report_dir / f"readiness_{timestamp}.md"
    summary = summarize(findings)
    lines = [
        "# AgentSploit LAN Readiness Report",
        "",
        f"- Target: `{profile.chat_url}`",
        f"- Verdict: `{summary['verdict']}`",
        f"- Total checks: `{summary['total']}`",
        "",
        "## Verdict Reasons",
        "",
    ]
    lines.extend(f"- {reason}" for reason in summary["verdict_reasons"])
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Check | Status | Severity | OWASP | Title | Evidence | Recommendation |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in findings:
        lines.append(
            "| "
            f"{markdown_escape(item.check_id)} | "
            f"{markdown_escape(item.status)} | "
            f"{markdown_escape(item.severity)} | "
            f"{markdown_escape(item.owasp_id or '-')} | "
            f"{markdown_escape(item.title)} | "
            f"{markdown_escape(', '.join(item.evidence[:5]))} | "
            f"{markdown_escape(item.recommendation)} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def save_html_report(findings: list[ReadinessFinding], profile: TargetProfile, report_dir: Path, timestamp: str) -> Path:
    path = report_dir / f"readiness_{timestamp}.html"
    summary = summarize(findings)
    rows = []
    for item in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.check_id)}</td>"
            f"<td>{html.escape(item.status)}</td>"
            f"<td>{html.escape(item.severity)}</td>"
            f"<td>{html.escape(item.owasp_id or '-')}</td>"
            f"<td>{html.escape(item.title)}</td>"
            f"<td>{html.escape(', '.join(item.evidence[:5]))}</td>"
            "</tr>"
        )
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AgentSploit LAN Readiness</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; }}
    th {{ background: #f3f4f6; }}
    .verdict {{ font-size: 1.5rem; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>AgentSploit LAN Readiness Report</h1>
  <p><strong>Target:</strong> <code>{html.escape(profile.chat_url)}</code></p>
  <p class="verdict">Verdict: {html.escape(summary['verdict'])}</p>
  <ul>{''.join(f'<li>{html.escape(reason)}</li>' for reason in summary['verdict_reasons'])}</ul>
  <table>
    <tr><th>Check</th><th>Status</th><th>Severity</th><th>OWASP</th><th>Title</th><th>Evidence</th></tr>
    {''.join(rows)}
  </table>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")
    return path


def save_reports(findings: list[ReadinessFinding], profile: TargetProfile, report_dir: Path) -> tuple[Path, Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return (
        save_json_report(findings, profile, report_dir, timestamp),
        save_markdown_report(findings, profile, report_dir, timestamp),
        save_html_report(findings, profile, report_dir, timestamp),
    )


def run_readiness(profile: TargetProfile, payloads: list[dict[str, Any]]) -> list[ReadinessFinding]:
    timeout = httpx.Timeout(profile.timeout)
    with httpx.Client(timeout=timeout) as client:
        findings = run_http_checks(client, profile)
        if any(item.check_id == "HTTP-001" and item.status == "FAIL" for item in findings):
            findings.extend(skipped_payload_checks(payloads, "The chat endpoint is not reachable."))
            return findings

        findings.extend(run_payload_checks(client, profile, payloads))
        return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assess whether an LLM agent is ready for LAN exposure.")
    parser.add_argument("--target", help="Chat endpoint URL to assess.")
    parser.add_argument("--config", type=Path, help="Target profile JSON file.")
    parser.add_argument("--payloads", type=Path, default=DEFAULT_PAYLOAD_FILE, help="Readiness payload file.")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR, help="Report output directory.")
    parser.add_argument("--profile", choices=["lan-basic", "lan-standard"], default="lan-standard")
    parser.add_argument("--no-audit", action="store_true", help="Disable audit log correlation.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = load_target_profile(args.config, args.target, args.no_audit)
    _, payloads = load_payload_file(args.payloads)
    if args.profile == "lan-basic":
        payloads = payloads[:5]

    console.print(f"[bold]Target:[/bold] {profile.chat_url}")
    console.print(f"[bold]Profile:[/bold] {args.profile}")
    console.print(f"[bold]Audit URL:[/bold] {profile.audit_url or 'disabled'}")
    console.print(f"[bold]Payloads:[/bold] {len(payloads)}")

    findings = run_readiness(profile, payloads)
    summary = summarize(findings)
    console.print()
    console.print(build_table(findings))
    console.print(f"\n[bold]Verdict:[/bold] {summary['verdict']}")
    for reason in summary["verdict_reasons"]:
        console.print(f"- {reason}")

    json_path, markdown_path, html_path = save_reports(findings, profile, args.report_dir)
    console.print(f"\n[bold green]JSON report saved:[/bold green] {json_path}")
    console.print(f"[bold green]Markdown report saved:[/bold green] {markdown_path}")
    console.print(f"[bold green]HTML report saved:[/bold green] {html_path}")

    return 1 if summary["verdict"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
