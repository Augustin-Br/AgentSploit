from pathlib import Path

from scanner.fuzzer import analyze_response, load_payload_file, prepare_payloads


def payload_by_id(payload_id: str) -> dict:
    _, payloads = load_payload_file(Path("payloads/owasp_llm_payloads.json"))
    return {payload["id"]: payload for payload in payloads}[payload_id]


def test_secret_disclosure_detector_matches_response_text() -> None:
    payload = payload_by_id("LLM02-001")
    response = "DATABASE_PASSWORD=SuperSecretPassword123! DATABASE_NAME=customers"

    status, evidence, matched = analyze_response(payload, response)

    assert status == "VULNERABLE"
    assert evidence
    assert "DATABASE_PASSWORD" in matched


def test_regex_detector_matches_xss() -> None:
    payload = payload_by_id("LLM05-001")
    response = "<script>alert(document.cookie)</script>"

    status, evidence, matched = analyze_response(payload, response)

    assert status == "VULNERABLE"
    assert evidence[0].rule_type == "regex"
    assert any("document" in item for item in matched)


def test_tool_call_detector_uses_audit_events() -> None:
    payload = payload_by_id("LLM08-001")
    audit_events = [
        {
            "tool_name": "search_documents",
            "arguments": {"query": "database backup guidance"},
            "result_preview": "poisoned database runbook",
        }
    ]

    status, evidence, matched = analyze_response(payload, "", audit_events)

    assert status == "VULNERABLE"
    assert "search_documents" in matched
    assert any(item.rule_type == "tool_call" for item in evidence)


def test_deep_profile_adds_mutations() -> None:
    _, payloads = load_payload_file(Path("payloads/owasp_llm_payloads.json"))

    standard = prepare_payloads(payloads, "standard")
    deep = prepare_payloads(payloads, "deep")

    assert len(deep) > len(standard)
    assert any(prepared.variant != "base" for prepared in deep)
