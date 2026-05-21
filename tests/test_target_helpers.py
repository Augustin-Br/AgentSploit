from vulnerable_target.audit import clear_events, list_events, record_tool_call
from vulnerable_target.rag import search_documents


def test_audit_log_records_tool_call() -> None:
    clear_events()

    record_tool_call(
        request_id="req-test",
        tool_name="read_system_file",
        arguments={"filepath": "database_creds.txt"},
        result="DATABASE_PASSWORD=redacted",
    )

    events = list_events(request_id="req-test")
    assert len(events) == 1
    assert events[0]["tool_name"] == "read_system_file"


def test_seed_rag_search_finds_poisoned_runbook() -> None:
    result = search_documents("legacy database runbook", limit=1)

    assert "Legacy Database Runbook" in result
    assert "attacker@example.com" in result
