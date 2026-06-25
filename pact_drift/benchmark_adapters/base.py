from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BenchmarkAdapter(ABC):
    name: str
    version: str = "v1"

    @abstractmethod
    def load_tool_schemas(self, **kwargs: Any) -> list[dict[str, Any]]:
        pass

    def normalize_tool_schema(self, raw_tool: Any) -> dict[str, Any]:
        return raw_tool

    def infer_domain_aliases(self, tool_schema: dict[str, Any]) -> dict[str, str]:
        return {}

    def postprocess_tool_contract(self, tool_schema: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
        return contract
