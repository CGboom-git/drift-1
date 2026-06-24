from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Literal

ToolType = Literal["READ_LOW", "READ_SENSITIVE", "ACTION"]
CheckMode = Literal["track_only", "control_check_and_track", "full"]


@dataclass
class ArgumentContract:
    role: str
    allow_model_generated: bool = True
    forbidden_origins: list[str] = field(default_factory=list)
    min_trust: str | None = None
    description: str | None = None


@dataclass
class ToolContract:
    tool_name: str
    tool_type: ToolType
    check_mode: CheckMode
    arguments: dict[str, ArgumentContract] = field(default_factory=dict)
    output_policy: dict[str, Any] = field(default_factory=dict)
    description: str | None = None


@dataclass
class GlobalToolContracts:
    contract_version: str
    schema_hash: str
    generated_by: dict[str, Any]
    tools: dict[str, ToolContract]
    # Per-tool hashes let a suite runtime verify its subset of a frozen global contract.
    tool_schema_hashes: dict[str, str] = field(default_factory=dict)


@dataclass
class TaskArgumentConstraint:
    must_derive_from: str | None = None
    upstream_must_derive_from: str | None = None
    allowed_sources: list[str] = field(default_factory=list)
    forbidden_sources: list[str] = field(default_factory=list)


@dataclass
class TaskContract:
    allowed_trajectory: list[str]
    task_delegation: dict[str, Any] = field(default_factory=dict)
    argument_source_constraints: dict[str, TaskArgumentConstraint] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return contracts_to_jsonable(self)


_TOOL_TYPES = {"READ_LOW", "READ_SENSITIVE", "ACTION"}
_CHECK_MODES = {"track_only", "control_check_and_track", "full"}


def contracts_to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return {key: contracts_to_jsonable(value) for key, value in asdict(obj).items()}
    if isinstance(obj, dict):
        return {key: contracts_to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [contracts_to_jsonable(value) for value in obj]
    return obj


def validate_global_contracts_schema(data: dict[str, Any]) -> None:
    for field_name in ("contract_version", "schema_hash", "generated_by", "tools"):
        if field_name not in data:
            raise ValueError(f"Global tool contract is missing required field '{field_name}'.")
    if not isinstance(data["tools"], dict) or not data["tools"]:
        raise ValueError("Global tool contract field 'tools' must be a non-empty object.")
    for name, tool in data["tools"].items():
        for field_name in ("tool_name", "tool_type", "check_mode", "arguments"):
            if field_name not in tool:
                raise ValueError(f"Tool contract '{name}' is missing '{field_name}'.")
        if tool["tool_type"] not in _TOOL_TYPES:
            raise ValueError(f"Tool contract '{name}' has invalid tool_type '{tool['tool_type']}'.")
        if tool["check_mode"] not in _CHECK_MODES:
            raise ValueError(f"Tool contract '{name}' has invalid check_mode '{tool['check_mode']}'.")
        if not isinstance(tool["arguments"], dict):
            raise ValueError(f"Tool contract '{name}' arguments must be an object.")
        for argument, argument_contract in tool["arguments"].items():
            if "role" not in argument_contract:
                raise ValueError(f"Tool contract '{name}.{argument}' is missing 'role'.")


def global_contracts_from_json(data: dict[str, Any]) -> GlobalToolContracts:
    validate_global_contracts_schema(data)
    tools = {
        name: ToolContract(
            tool_name=tool["tool_name"],
            tool_type=tool["tool_type"],
            check_mode=tool["check_mode"],
            arguments={
                argument: ArgumentContract(**argument_contract)
                for argument, argument_contract in tool.get("arguments", {}).items()
            },
            output_policy=tool.get("output_policy", {}),
            description=tool.get("description"),
        )
        for name, tool in data["tools"].items()
    }
    return GlobalToolContracts(
        contract_version=data["contract_version"],
        schema_hash=data["schema_hash"],
        generated_by=data["generated_by"],
        tools=tools,
        tool_schema_hashes=data.get("tool_schema_hashes", {}),
    )


def task_contract_from_json(data: dict[str, Any]) -> TaskContract:
    return TaskContract(
        allowed_trajectory=data.get("allowed_trajectory", []),
        task_delegation=data.get("task_delegation", {}),
        argument_source_constraints={
            key: TaskArgumentConstraint(**value)
            for key, value in data.get("argument_source_constraints", {}).items()
        },
    )


def load_global_contracts(path: str) -> GlobalToolContracts:
    with Path(path).open("r", encoding="utf-8") as handle:
        return global_contracts_from_json(json.load(handle))


def save_global_contracts(contracts: GlobalToolContracts, path: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(contracts_to_jsonable(contracts), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
