from __future__ import annotations

from typing import Any

from agentdojo.task_suite.load_suites import get_suite

from pact_drift.benchmark_adapters.base import BenchmarkAdapter
from pact_drift.schema_utils import collect_tool_schemas_from_functions


class AgentDojoAdapter(BenchmarkAdapter):
    name = "agentdojo"
    version = "v1"

    def load_tool_schemas(self, **kwargs: Any) -> list[dict[str, Any]]:
        benchmark_version = kwargs.get("benchmark_version", "v1.2")
        suites = kwargs.get("suites", ["banking", "slack", "travel", "workspace"])
        schemas_by_name: dict[str, dict[str, Any]] = {}
        for suite_name in suites:
            suite = get_suite(benchmark_version, suite_name)
            for schema in collect_tool_schemas_from_functions(suite.tools):
                normalized = self.normalize_tool_schema(schema)
                schemas_by_name[normalized["name"]] = normalized
        return list(sorted(schemas_by_name.values(), key=lambda schema: schema["name"]))

    def normalize_tool_schema(self, raw_tool: Any) -> dict[str, Any]:
        return {
            "name": raw_tool["name"],
            "description": raw_tool.get("description", ""),
            "parameters": raw_tool.get("parameters", {}),
        }

    def infer_domain_aliases(self, tool_schema: dict[str, Any]) -> dict[str, str]:
        del tool_schema
        return {
            "unrequested_transaction_history": "unauthorized_tool_output",
            "slack_injection_message": "injected_instruction",
            "file_raw_content": "raw_external_content",
        }
