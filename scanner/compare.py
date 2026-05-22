import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    PROJECT_ROOT = Path(__file__).resolve().parents[1]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
else:
    PROJECT_ROOT = Path(__file__).resolve().parents[1]

from rich.console import Console
from rich.table import Table

from scanner.fuzzer import (
    DEFAULT_PAYLOAD_FILE,
    DEFAULT_REPORT_DIR,
    derive_audit_url,
    load_payload_file,
    prepare_payloads,
    run_scan,
)


console = Console()
DEFAULT_BASELINE = "http://127.0.0.1:8000/chat"
DEFAULT_HARDENED = "http://127.0.0.1:8001/chat"


def load_report_results(path: Path) -> list[dict[str, Any]]:
    """Load fuzzer results from an existing JSON report."""

    data = json.loads(path.read_text(encoding="utf-8"))
    results = data.get("results", [])
    if not isinstance(results, list):
        raise RuntimeError(f"Report {path} does not contain a results list.")
    return [item for item in results if isinstance(item, dict)]


def normalize_results(results: list[Any]) -> list[dict[str, Any]]:
    """Convert dataclass or dict scan results to plain dictionaries."""

    normalized = []
    for result in results:
        if isinstance(result, dict):
            normalized.append(result)
        else:
            normalized.append(asdict(result))
    return normalized


def _vulnerable(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [result for result in results if result.get("status") == "VULNERABLE"]


def _by_payload_id(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(result.get("payload_id")): result for result in results}


def build_comparison_report(
    baseline_results: list[dict[str, Any]],
    hardened_results: list[dict[str, Any]],
    *,
    baseline_target: str,
    hardened_target: str,
) -> dict[str, Any]:
    """Aggregate before/after fuzzer results."""

    baseline_by_id = _by_payload_id(baseline_results)
    hardened_by_id = _by_payload_id(hardened_results)
    payload_ids = sorted(set(baseline_by_id) | set(hardened_by_id))

    blocked = []
    remaining = []
    new_findings = []
    changed = []

    for payload_id in payload_ids:
        baseline = baseline_by_id.get(payload_id)
        hardened = hardened_by_id.get(payload_id)
        baseline_status = baseline.get("status") if baseline else "missing"
        hardened_status = hardened.get("status") if hardened else "missing"

        item = {
            "payload_id": payload_id,
            "name": (baseline or hardened or {}).get("name", ""),
            "owasp_id": (baseline or hardened or {}).get("owasp_id", ""),
            "severity": (baseline or hardened or {}).get("severity", ""),
            "baseline_status": baseline_status,
            "hardened_status": hardened_status,
        }
        changed.append(item)

        if baseline_status == "VULNERABLE" and hardened_status != "VULNERABLE":
            blocked.append(item)
        elif baseline_status == "VULNERABLE" and hardened_status == "VULNERABLE":
            remaining.append(item)
        elif baseline_status != "VULNERABLE" and hardened_status == "VULNERABLE":
            new_findings.append(item)

    baseline_count = len(_vulnerable(baseline_results))
    hardened_count = len(_vulnerable(hardened_results))
    if new_findings:
        verdict = "REGRESSION"
    elif hardened_count == 0 and baseline_count > 0:
        verdict = "MITIGATED"
    elif hardened_count < baseline_count:
        verdict = "IMPROVED"
    elif hardened_count == baseline_count:
        verdict = "UNCHANGED"
    else:
        verdict = "NEEDS_REVIEW"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_target": baseline_target,
        "hardened_target": hardened_target,
        "summary": {
            "baseline_findings": baseline_count,
            "hardened_findings": hardened_count,
            "blocked_findings": len(blocked),
            "remaining_findings": len(remaining),
            "new_findings": len(new_findings),
            "verdict": verdict,
            "baseline_by_status": dict(Counter(result.get("status", "unknown") for result in baseline_results)),
            "hardened_by_status": dict(Counter(result.get("status", "unknown") for result in hardened_results)),
        },
        "blocked_findings": blocked,
        "remaining_findings": remaining,
        "new_findings": new_findings,
        "results": changed,
    }


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def save_json_report(report: dict[str, Any], report_dir: Path, timestamp: str) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"compare_{timestamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def save_markdown_report(report: dict[str, Any], report_dir: Path, timestamp: str) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"compare_{timestamp}.md"
    summary = report["summary"]
    lines = [
        "# AgentSploit Before/After Comparison",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Baseline target: `{report['baseline_target']}`",
        f"- Hardened target: `{report['hardened_target']}`",
        f"- Verdict: `{summary['verdict']}`",
        f"- Baseline findings: `{summary['baseline_findings']}`",
        f"- Hardened findings: `{summary['hardened_findings']}`",
        f"- Blocked findings: `{summary['blocked_findings']}`",
        f"- Remaining findings: `{summary['remaining_findings']}`",
        f"- New findings: `{summary['new_findings']}`",
        "",
        "## Blocked Findings",
        "",
        "| Payload | OWASP | Severity | Name |",
        "| --- | --- | --- | --- |",
    ]
    if report["blocked_findings"]:
        for item in report["blocked_findings"]:
            lines.append(
                "| "
                f"{markdown_escape(str(item['payload_id']))} | "
                f"{markdown_escape(str(item['owasp_id']))} | "
                f"{markdown_escape(str(item['severity']))} | "
                f"{markdown_escape(str(item['name']))} |"
            )
    else:
        lines.append("| - | - | - | No baseline findings were mitigated. |")

    lines.extend(
        [
            "",
            "## Remaining Findings",
            "",
            "| Payload | OWASP | Severity | Name |",
            "| --- | --- | --- | --- |",
        ]
    )
    if report["remaining_findings"]:
        for item in report["remaining_findings"]:
            lines.append(
                "| "
                f"{markdown_escape(str(item['payload_id']))} | "
                f"{markdown_escape(str(item['owasp_id']))} | "
                f"{markdown_escape(str(item['severity']))} | "
                f"{markdown_escape(str(item['name']))} |"
            )
    else:
        lines.append("| - | - | - | No remaining before/after findings. |")

    if report["new_findings"]:
        lines.extend(["", "## New Findings", "", "| Payload | OWASP | Severity | Name |", "| --- | --- | --- | --- |"])
        for item in report["new_findings"]:
            lines.append(
                "| "
                f"{markdown_escape(str(item['payload_id']))} | "
                f"{markdown_escape(str(item['owasp_id']))} | "
                f"{markdown_escape(str(item['severity']))} | "
                f"{markdown_escape(str(item['name']))} |"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build_table(report: dict[str, Any]) -> Table:
    summary = report["summary"]
    table = Table(title="AgentSploit Before/After")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Baseline findings", str(summary["baseline_findings"]))
    table.add_row("Hardened findings", str(summary["hardened_findings"]))
    table.add_row("Blocked findings", str(summary["blocked_findings"]))
    table.add_row("Remaining findings", str(summary["remaining_findings"]))
    table.add_row("New findings", str(summary["new_findings"]))
    table.add_row("Verdict", str(summary["verdict"]))
    return table


def scan_target(target: str, payload_file: Path, profile: str, timeout: float, delay: float, no_audit: bool) -> list[dict[str, Any]]:
    metadata, payloads = load_payload_file(payload_file)
    prepared = prepare_payloads(payloads, profile)
    audit_url = None if no_audit else derive_audit_url(target)
    console.print(f"[bold]Scanning:[/bold] {target} ({len(prepared)} payloads)")
    return normalize_results(
        run_scan(
            prepared_payloads=prepared,
            target_url=target,
            audit_url=audit_url,
            timeout=timeout,
            delay=delay,
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare vulnerable and hardened AgentSploit fuzzer results.")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE, help=f"Baseline chat URL. Default: {DEFAULT_BASELINE}")
    parser.add_argument("--hardened", default=DEFAULT_HARDENED, help=f"Hardened chat URL. Default: {DEFAULT_HARDENED}")
    parser.add_argument("--baseline-report", type=Path, help="Existing baseline scan_*.json report.")
    parser.add_argument("--hardened-report", type=Path, help="Existing hardened scan_*.json report.")
    parser.add_argument("--payloads", type=Path, default=DEFAULT_PAYLOAD_FILE, help="Payload JSON file.")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR, help="Report output directory.")
    parser.add_argument("--profile", choices=["quick", "standard", "deep"], default="quick", help="Fuzzer profile.")
    parser.add_argument("--timeout", type=float, default=45.0, help="HTTP timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between payloads.")
    parser.add_argument("--no-audit", action="store_true", help="Disable audit log correlation for both targets.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        baseline_results = (
            load_report_results(args.baseline_report)
            if args.baseline_report
            else scan_target(args.baseline, args.payloads, args.profile, args.timeout, args.delay, args.no_audit)
        )
        if not args.baseline_report:
            time.sleep(max(0.0, args.delay))
        hardened_results = (
            load_report_results(args.hardened_report)
            if args.hardened_report
            else scan_target(args.hardened, args.payloads, args.profile, args.timeout, args.delay, args.no_audit)
        )
    except RuntimeError as exc:
        console.print(f"[bold red]Comparison failed:[/bold red] {exc}")
        return 1

    report = build_comparison_report(
        baseline_results=baseline_results,
        hardened_results=hardened_results,
        baseline_target=args.baseline,
        hardened_target=args.hardened,
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = save_json_report(report, args.report_dir, timestamp)
    markdown_path = save_markdown_report(report, args.report_dir, timestamp)

    console.print()
    console.print(build_table(report))
    console.print(f"\n[bold green]JSON report saved:[/bold green] {json_path}")
    console.print(f"[bold green]Markdown report saved:[/bold green] {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
