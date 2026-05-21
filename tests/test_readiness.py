import json
from pathlib import Path

import httpx

from scanner.readiness import (
    TargetProfile,
    build_chat_body,
    calculate_verdict,
    check_authentication,
    check_cors,
    get_nested,
    load_target_profile,
    run_readiness,
    save_reports,
)


def sample_profile() -> TargetProfile:
    return TargetProfile(
        name="test",
        chat_url="http://agent.local/chat",
        method="POST",
        headers={"Content-Type": "application/json"},
        message_field="message",
        messages_field="messages",
        response_path="response",
        request_id_path="request_id",
        audit_url=None,
        supports_multi_turn=True,
        feature_endpoints={},
        timeout=5,
        rate_limit_requests=2,
        delay=0,
    )


def test_get_nested_reads_dot_path() -> None:
    assert get_nested({"a": {"b": "value"}}, "a.b") == "value"
    assert get_nested({"a": {}}, "a.b") is None


def test_load_target_profile_from_config(tmp_path: Path) -> None:
    config = tmp_path / "targets.json"
    config.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "name": "demo",
                        "chat_url": "http://127.0.0.1:8000/chat",
                        "request": {"message_field": "prompt"},
                        "response_path": "answer",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    profile = load_target_profile(config, None, no_audit=True)

    assert profile.name == "demo"
    assert profile.message_field == "prompt"
    assert profile.response_path == "answer"
    assert profile.audit_url is None


def test_build_chat_body_supports_single_and_multi_turn() -> None:
    profile = sample_profile()

    single = build_chat_body(profile, [{"role": "user", "content": "hello"}])
    multi = build_chat_body(
        profile,
        [
            {"role": "user", "content": "first"},
            {"role": "user", "content": "second"},
        ],
    )

    assert single == {"message": "hello"}
    assert multi["messages"][1]["content"] == "second"


def test_calculate_verdict_blocks_on_high_fail() -> None:
    from scanner.readiness import finding

    findings = [
        finding(
            check_id="X",
            category="HTTP",
            status="FAIL",
            severity="high",
            title="No auth",
            evidence=["HTTP 200"],
            recommendation="Add auth",
        )
    ]

    verdict, reasons = calculate_verdict(findings)

    assert verdict == "FAIL"
    assert "No auth" in reasons[0]


def test_http_checks_can_use_mock_transport() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"access-control-allow-origin": "*"})
        return httpx.Response(200, json={"response": "OK"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    profile = sample_profile()

    auth = check_authentication(client, profile)
    cors = check_cors(client, profile)

    assert auth.status == "FAIL"
    assert cors.status == "FAIL"


def test_save_reports_writes_three_files(tmp_path: Path) -> None:
    from scanner.readiness import finding

    profile = sample_profile()
    findings = [
        finding(
            check_id="OK",
            category="HTTP",
            status="PASS",
            severity="info",
            title="Reachable",
            evidence=["ok"],
            recommendation="none",
        )
    ]

    paths = save_reports(findings, profile, tmp_path)

    assert len(paths) == 3
    assert all(path.exists() for path in paths)


def test_unreachable_target_skips_payload_checks() -> None:
    profile = sample_profile()
    profile.chat_url = "http://127.0.0.1:9/chat"
    profile.timeout = 0.1
    payloads = [{"id": "READY-TEST", "name": "Payload should skip", "owasp_id": "LLM01:2025"}]

    findings = run_readiness(profile, payloads)

    assert any(item.check_id == "HTTP-001" and item.status == "FAIL" for item in findings)
    assert any(item.check_id == "READY-TEST" and item.status == "SKIPPED" for item in findings)
