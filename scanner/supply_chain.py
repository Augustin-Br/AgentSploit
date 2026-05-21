import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.table import Table


PROJECT_ROOT = Path(__file__).resolve().parents[1]
console = Console()

SECRET_PATTERNS = {
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "quoted_secret_assignment": re.compile(
        r"(?i)\b(password|secret|api[_-]?key)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
    ),
    "env_secret_assignment": re.compile(
        r"(?im)^\s*[A-Z0-9_]*(PASSWORD|SECRET|API_KEY)\s*=\s*[^\s#]{8,}"
    ),
}

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "reports", ".pytest_cache"}
SKIP_FILES = {".env"}
LAB_FIXTURE_PATHS = {
    "database_creds.txt",
    "tests/test_fuzzer_detectors.py",
    "tests/test_target_helpers.py",
}


@dataclass
class SupplyChainFinding:
    check_id: str
    severity: str
    title: str
    path: str
    detail: str
    recommendation: str


def iter_project_files(root: Path, include_lab_fixtures: bool = False) -> Iterable[Path]:
    """Yield project files while skipping virtualenvs and generated data."""

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if not include_lab_fixtures and str(path.relative_to(root)) in LAB_FIXTURE_PATHS:
            continue
        yield path


def redact(value: str) -> str:
    """Avoid printing real secrets in reports."""

    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def check_gitignore(root: Path) -> list[SupplyChainFinding]:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return [
            SupplyChainFinding(
                check_id="SC-001",
                severity="high",
                title="Missing .gitignore",
                path=".gitignore",
                detail="No .gitignore file was found.",
                recommendation="Ignore .env, virtualenvs, reports, caches, and runtime data.",
            )
        ]

    content = gitignore.read_text(encoding="utf-8")
    findings = []
    for required in [".env", ".venv/", "reports/*"]:
        if required not in content:
            findings.append(
                SupplyChainFinding(
                    check_id="SC-002",
                    severity="medium",
                    title="Missing ignore rule",
                    path=".gitignore",
                    detail=f"Expected ignore rule {required!r} was not found.",
                    recommendation="Add the missing ignore rule to reduce accidental secret or artifact commits.",
                )
            )

    return findings


def check_requirements(root: Path) -> list[SupplyChainFinding]:
    requirements = root / "requirements.txt"
    if not requirements.exists():
        return []

    findings = []
    for line_number, line in enumerate(requirements.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "==" not in stripped and not stripped.startswith("-"):
            findings.append(
                SupplyChainFinding(
                    check_id="SC-003",
                    severity="low",
                    title="Unpinned dependency",
                    path=f"requirements.txt:{line_number}",
                    detail=f"Dependency {stripped!r} is not pinned.",
                    recommendation="For reproducible portfolio demos, pin versions once the lab stabilizes.",
                )
            )

    return findings


def check_secrets(root: Path = PROJECT_ROOT, include_lab_fixtures: bool = False) -> list[SupplyChainFinding]:
    findings = []
    for path in iter_project_files(root, include_lab_fixtures=include_lab_fixtures):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        relative = str(path.relative_to(root))
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                findings.append(
                    SupplyChainFinding(
                        check_id="SC-004",
                        severity="high",
                        title="Potential secret in project file",
                        path=relative,
                        detail=f"{name} matched value {redact(match.group(0))}",
                        recommendation="Move secrets to .env and ensure the file is ignored by git.",
                    )
                )

    return findings


def run_pip_audit(root: Path) -> list[SupplyChainFinding]:
    """Run pip-audit if installed; skip gracefully otherwise."""

    try:
        completed = subprocess.run(
            ["python", "-m", "pip_audit", "-r", str(root / "requirements.txt"), "-f", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if completed.returncode == 0 or not completed.stdout.strip():
        return []

    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for dependency in data.get("dependencies", []):
        for vulnerability in dependency.get("vulns", []):
            findings.append(
                SupplyChainFinding(
                    check_id="SC-005",
                    severity="high",
                    title="Known vulnerable dependency",
                    path="requirements.txt",
                    detail=f"{dependency.get('name')} {dependency.get('version')} - {vulnerability.get('id')}",
                    recommendation="Upgrade the affected dependency or document why it is acceptable for the lab.",
                )
            )

    return findings


def build_table(findings: list[SupplyChainFinding]) -> Table:
    table = Table(title="AgentSploit Supply Chain Checks")
    table.add_column("Check", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    table.add_column("Path")

    for finding in findings:
        table.add_row(finding.check_id, finding.severity, finding.title, finding.path)

    return table


def save_report(findings: list[SupplyChainFinding], report_dir: Path) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"supply_chain_{timestamp}.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(findings),
            "high": sum(1 for finding in findings if finding.severity == "high"),
            "medium": sum(1 for finding in findings if finding.severity == "medium"),
            "low": sum(1 for finding in findings if finding.severity == "low"),
        },
        "findings": [asdict(finding) for finding in findings],
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static supply-chain and hygiene checks for AgentSploit.")
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT, help="Project root to scan.")
    parser.add_argument("--report-dir", type=Path, default=PROJECT_ROOT / "reports", help="Report output directory.")
    parser.add_argument("--skip-pip-audit", action="store_true", help="Skip optional pip-audit integration.")
    parser.add_argument(
        "--include-lab-fixtures",
        action="store_true",
        help="Also scan intentional vulnerable lab fixtures such as database_creds.txt and tests.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = []
    findings.extend(check_gitignore(args.root))
    findings.extend(check_requirements(args.root))
    findings.extend(check_secrets(args.root, include_lab_fixtures=args.include_lab_fixtures))
    if not args.skip_pip_audit:
        findings.extend(run_pip_audit(args.root))

    console.print(build_table(findings))
    report_path = save_report(findings, args.report_dir)
    console.print(f"\n[bold green]Supply chain report saved:[/bold green] {report_path}")
    return 1 if any(finding.severity == "high" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
