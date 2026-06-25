from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Literal

ToolType = Literal["READ_LOW", "READ_SENSITIVE", "ACTION"]
CheckMode = Literal["track_only", "control_check_and_track", "full"]
Role = Literal["target", "command", "credential", "content", "selector", "control"]
Trust = Literal["TRUSTED", "USER", "DELEGATED", "TOOL_OUTPUT", "EXTERNAL"]

CONTRACT_VERSION = "pact_drift_l2_draft_v1"
GENERATION_MODE = "offline_heuristic"
TRUST_LATTICE = ["TRUSTED", "USER", "DELEGATED", "TOOL_OUTPUT", "EXTERNAL"]
ROLES = ["target", "command", "credential", "content", "selector", "control"]
TOOL_TYPES = ["READ_LOW", "READ_SENSITIVE", "ACTION"]
CHECK_MODES = ["track_only", "control_check_and_track", "full"]
FORBIDDEN_ORIGIN_TYPES = [
    "model_guess",
    "injected_instruction",
    "untrusted_raw_text",
    "unauthorized_sensitive_read",
    "unrequested_transaction_history",
    "default_without_authorization",
    "credential_leakage",
    "cross_user_data",
    "tool_error_or_exception",
    "unknown_origin",
]
OBLIGATION_TYPES = [
    "authorized_destination",
    "authorized_command",
    "authorized_credential_use",
    "authorized_object_selection",
    "authorized_control_value",
    "non_instructional_content",
    "task_relevance",
    "no_policy_override",
    "no_external_redirection",
    "structured_field_required",
]
DISCHARGE_PROCEDURES = [
    "user_explicit",
    "task_delegation",
    "structured_extraction",
    "trusted_tool_derivation",
    "exact_match_to_authorized_source",
    "schema_validated_parse",
]
FORBIDDEN_DISCHARGE_PROCEDURES = {"user_confirmation", "human_approval", "policy_allowlist", "none"}


@dataclass
class L2ArgumentContract:
    name: str
    role: str
    tau_min: str
    F: list[str] = field(default_factory=list)
    R: list[str] = field(default_factory=list)
    D: list[str] = field(default_factory=list)
    heuristic_reason: str | None = None


@dataclass
class L2ToolContract:
    tool_name: str
    tool_type: str
    check_mode: str
    args: dict[str, L2ArgumentContract] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    heuristic_reason: str | None = None


@dataclass
class L2GlobalContracts:
    contract_version: str
    generation_mode: str
    schema_hash: str
    trust_lattice: list[str]
    roles: list[str]
    forbidden_origin_types: list[str]
    obligation_types: list[str]
    discharge_procedures: list[str]
    generated_by: dict[str, Any]
    tools: dict[str, L2ToolContract]
    tool_schema_hashes: dict[str, str] = field(default_factory=dict)


def l2_to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return {key: l2_to_jsonable(value) for key, value in asdict(obj).items()}
    if isinstance(obj, dict):
        return {key: l2_to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [l2_to_jsonable(value) for value in obj]
    return obj


def save_l2_global_contracts(contracts: L2GlobalContracts, path: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(l2_to_jsonable(contracts), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def load_l2_global_contracts(path: str) -> L2GlobalContracts:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    validate_l2_global_contracts_schema(data)
    return L2GlobalContracts(
        contract_version=data["contract_version"],
        generation_mode=data["generation_mode"],
        schema_hash=data["schema_hash"],
        trust_lattice=list(data["trust_lattice"]),
        roles=list(data["roles"]),
        forbidden_origin_types=list(data["forbidden_origin_types"]),
        obligation_types=list(data["obligation_types"]),
        discharge_procedures=list(data["discharge_procedures"]),
        generated_by=dict(data["generated_by"]),
        tools={name: _tool_from_json(value) for name, value in data["tools"].items()},
        tool_schema_hashes=dict(data.get("tool_schema_hashes", {})),
    )


def validate_l2_global_contracts_schema(data: dict[str, Any]) -> None:
    for field_name in (
        "contract_version",
        "generation_mode",
        "schema_hash",
        "trust_lattice",
        "roles",
        "forbidden_origin_types",
        "obligation_types",
        "discharge_procedures",
        "generated_by",
        "tools",
    ):
        if field_name not in data:
            raise ValueError(f"L2 global contract is missing required field '{field_name}'.")
    if data["roles"] != ROLES:
        raise ValueError("L2 roles must match the fixed role enum.")
    if data["trust_lattice"] != TRUST_LATTICE:
        raise ValueError("L2 trust lattice must match the fixed trust enum and order.")
    if data["forbidden_origin_types"] != FORBIDDEN_ORIGIN_TYPES:
        raise ValueError("L2 forbidden origin enum must match the fixed enum.")
    if data["obligation_types"] != OBLIGATION_TYPES:
        raise ValueError("L2 obligation enum must match the fixed enum.")
    if data["discharge_procedures"] != DISCHARGE_PROCEDURES:
        raise ValueError("L2 discharge procedure enum must match the fixed enum.")
    if not isinstance(data["tools"], dict) or not data["tools"]:
        raise ValueError("L2 global contract field 'tools' must be a non-empty object.")
    for tool_name, tool in data["tools"].items():
        _validate_l2_tool_contract(tool_name, tool)


def _tool_from_json(data: dict[str, Any]) -> L2ToolContract:
    return L2ToolContract(
        tool_name=data["tool_name"],
        tool_type=data["tool_type"],
        check_mode=data["check_mode"],
        args={name: _argument_from_json(value) for name, value in data.get("args", {}).items()},
        output=dict(data.get("output", {})),
        heuristic_reason=data.get("heuristic_reason"),
    )


def _argument_from_json(data: dict[str, Any]) -> L2ArgumentContract:
    return L2ArgumentContract(
        name=data["name"],
        role=data["role"],
        tau_min=data["tau_min"],
        F=list(data.get("F", [])),
        R=list(data.get("R", [])),
        D=list(data.get("D", [])),
        heuristic_reason=data.get("heuristic_reason"),
    )


def _validate_l2_tool_contract(tool_name: str, tool: dict[str, Any]) -> None:
    for field_name in ("tool_name", "tool_type", "check_mode", "args", "output"):
        if field_name not in tool:
            raise ValueError(f"L2 tool contract '{tool_name}' is missing '{field_name}'.")
    if tool["tool_type"] not in TOOL_TYPES:
        raise ValueError(f"L2 tool contract '{tool_name}' has invalid tool_type '{tool['tool_type']}'.")
    if tool["check_mode"] not in CHECK_MODES:
        raise ValueError(f"L2 tool contract '{tool_name}' has invalid check_mode '{tool['check_mode']}'.")
    if not isinstance(tool["args"], dict):
        raise ValueError(f"L2 tool contract '{tool_name}' args must be an object.")
    for argument_name, argument in tool["args"].items():
        _validate_l2_argument_contract(f"{tool_name}.{argument_name}", argument)


def _validate_l2_argument_contract(argument_path: str, argument: dict[str, Any]) -> None:
    for field_name in ("name", "role", "tau_min", "F", "R", "D"):
        if field_name not in argument:
            raise ValueError(f"L2 argument contract '{argument_path}' is missing '{field_name}'.")
    if argument["role"] not in ROLES:
        raise ValueError(f"L2 argument contract '{argument_path}' has invalid role '{argument['role']}'.")
    if argument["tau_min"] not in TRUST_LATTICE:
        raise ValueError(f"L2 argument contract '{argument_path}' has invalid tau_min '{argument['tau_min']}'.")
    for value in argument["F"]:
        if value not in FORBIDDEN_ORIGIN_TYPES:
            raise ValueError(f"L2 argument contract '{argument_path}' has invalid F value '{value}'.")
    for value in argument["R"]:
        if value not in OBLIGATION_TYPES:
            raise ValueError(f"L2 argument contract '{argument_path}' has invalid R value '{value}'.")
    for value in argument["D"]:
        if value not in DISCHARGE_PROCEDURES:
            raise ValueError(f"L2 argument contract '{argument_path}' has invalid D value '{value}'.")
        if value in FORBIDDEN_DISCHARGE_PROCEDURES:
            raise ValueError(f"L2 argument contract '{argument_path}' uses forbidden D value '{value}'.")
    if argument["role"] in {"financial_amount", "content_safety_critical"}:
        raise ValueError(f"L2 argument contract '{argument_path}' uses forbidden legacy role '{argument['role']}'.")
