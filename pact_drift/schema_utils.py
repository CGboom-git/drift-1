from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence


def _tool_schema(tool: Any) -> dict[str, Any]:
    parameters = tool.parameters.model_json_schema()
    return {"name": tool.name, "description": tool.description, "parameters": parameters}


def collect_tool_schemas_from_runtime(runtime: Any) -> list[dict[str, Any]]:
    return sorted((_tool_schema(tool) for tool in runtime.functions.values()), key=lambda tool: tool["name"])


def collect_tool_schemas_from_functions(functions: Sequence[Any]) -> list[dict[str, Any]]:
    return sorted((_tool_schema(tool) for tool in functions), key=lambda tool: tool["name"])


def canonicalize_tool_schema(tools: list[dict[str, Any]]) -> str:
    return json.dumps(tools, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compute_schema_hash(tools: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonicalize_tool_schema(tools).encode("utf-8")).hexdigest()


def compute_tool_schema_hash(tool: dict[str, Any]) -> str:
    return compute_schema_hash([tool])
