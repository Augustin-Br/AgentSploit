from typing import Any

from hardened_target.audit import record_tool_decision
from hardened_target.output_guard import looks_like_secret, sanitize_model_output
from hardened_target.policy import (
    DEFAULT_POLICY,
    PolicyConfig,
    is_email_allowed,
    is_file_read_allowed,
    is_sensitive_action_confirmed,
)
from hardened_target.tools import read_system_file, search_documents, send_email


class ToolGateway:
    """Authorize every tool invocation before local code is allowed to run."""

    def __init__(self, request_id: str, policy: PolicyConfig = DEFAULT_POLICY) -> None:
        self.request_id = request_id
        self.policy = policy
        self.tool_calls = 0

    def _block(self, tool_name: str, arguments: dict[str, Any], reason: str) -> str:
        result = f"I cannot perform that action. Hardened policy blocked it: {reason}."
        record_tool_decision(
            request_id=self.request_id,
            tool_name=tool_name,
            arguments=arguments,
            decision="BLOCK",
            reason=reason,
            result=result,
        )
        return result

    def _allow(self, tool_name: str, arguments: dict[str, Any], reason: str, result: str) -> str:
        guarded_result = sanitize_model_output(result, self.policy)
        record_tool_decision(
            request_id=self.request_id,
            tool_name=tool_name,
            arguments=arguments,
            decision="ALLOW",
            reason=reason,
            result=guarded_result,
        )
        return guarded_result

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool only if every gateway policy check passes."""

        if self.tool_calls >= self.policy.max_tool_calls_per_request:
            return self._block(tool_name, arguments, "tool call budget exceeded")

        self.tool_calls += 1

        if tool_name == "read_system_file":
            filepath = str(arguments.get("filepath", ""))
            decision = is_file_read_allowed(filepath, self.policy)
            if not decision.allowed:
                return self._block(tool_name, arguments, decision.reason)
            return self._allow(tool_name, arguments, decision.reason, read_system_file(filepath))

        if tool_name == "send_email":
            to = str(arguments.get("to", ""))
            domain_decision = is_email_allowed(to, self.policy)
            if not domain_decision.allowed:
                return self._block(tool_name, arguments, "recipient domain is not allowlisted")

            confirm_decision = is_sensitive_action_confirmed(tool_name, arguments, self.policy)
            if not confirm_decision.allowed:
                return self._block(tool_name, arguments, confirm_decision.reason)

            body = str(arguments.get("body", ""))
            if looks_like_secret(body):
                return self._block(tool_name, arguments, "message body resembles sensitive data")

            return self._allow(
                tool_name,
                arguments,
                "recipient and confirmation passed policy",
                send_email(
                    to=to,
                    subject=str(arguments.get("subject", "")),
                    body=body,
                ),
            )

        if tool_name == "search_documents":
            try:
                limit = int(arguments.get("limit", 3))
            except (TypeError, ValueError):
                limit = 3
            limit = max(1, min(limit, 5))
            result = search_documents(query=str(arguments.get("query", "")), limit=limit)
            return self._allow(tool_name, arguments, "RAG results sanitized as untrusted content", result)

        return self._block(tool_name, arguments, "unknown tool")
