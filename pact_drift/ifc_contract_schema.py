from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Literal

ToolType = Literal["READ_LOW", "READ_SENSITIVE", "ACTION"]
CheckMode = Literal["track_only", "control_check_and_track", "full"]
SinkRole = Literal["target", "command", "credential", "content", "selector", "control"]
IntegrityLabel = Literal["TRUSTED", "USER", "DELEGATED", "TOOL_OUTPUT", "EXTERNAL"]
ConfidentialityLabel = Literal["PUBLIC", "INTERNAL", "USER_PRIVATE", "SENSITIVE", "SECRET"]

CONTRACT_VERSION = "pact_drift_ifc_global_draft_v1"
GENERATION_MODE = "offline_heuristic"
INTEGRITY_LATTICE = ["TRUSTED", "USER", "DELEGATED", "TOOL_OUTPUT", "EXTERNAL"]
CONFIDENTIALITY_LATTICE = ["PUBLIC", "INTERNAL", "USER_PRIVATE", "SENSITIVE", "SECRET"]
SINK_ROLES = ["target", "command", "credential", "content", "selector", "control"]
TOOL_TYPES = ["READ_LOW", "READ_SENSITIVE", "ACTION"]
CHECK_MODES = ["track_only", "control_check_and_track", "full"]
SINK_SCOPES = ["none", "internal", "external", "public", "financial", "messaging", "calendar", "workspace", "credential", "booking"]
DENY_MARK_TYPES = [
    "model_inferred_unverified",
    "injected_instruction",
    "raw_external_content",
    "unauthorized_tool_output",
    "unauthorized_private_source",
    "cross_principal_data",
    "default_without_authorization",
    "credential_or_secret",
    "tool_error_or_exception",
    "unknown_origin",
    "policy_override_content",
    "stale_or_ambiguous_source",
]
FLOW_CONSTRAINT_TYPES = [
    "authorized_source",
    "authorized_destination",
    "authorized_object_selection",
    "authorized_control_value",
    "authorized_command",
    "authorized_credential_use",
    "structured_source_required",
    "trusted_derivation_required",
    "task_relevance",
    "non_instructional_content",
    "no_policy_override",
    "no_external_redirection",
    "no_private_to_public_sink",
    "destination_scope_match",
    "object_confidentiality_check",
    "minimal_disclosure",
]
ENDORSEMENT_TYPES = [
    "user_explicit",
    "task_delegation",
    "structured_extraction",
    "schema_validated_parse",
    "exact_match_to_authorized_source",
    "trusted_tool_derivation",
    "deterministic_transform",
    "source_object_binding",
]
DECLASSIFICATION_TYPES = [
    "explicit_output_delegation",
    "destination_scope_match",
    "content_minimization",
    "task_relevant_private_output",
    "schema_validated_export",
    "redaction_or_abstraction",
    "object_share_authorization",
]
FORBIDDEN_TOKENS = {
    "financial_amount",
    "content_safety_critical",
    "human_approval",
    "user_confirmation",
    "policy_allowlist",
    "unrequested_transaction_history",
}
LEGACY_KEYS = {"role", "tau_min", "F", "R", "D"}


@dataclass
class IFCArgumentContract:
    name: str
    sink_role: str
    I_min: str
    C_max: str
    deny_marks: list[str] = field(default_factory=list)
    flow_constraints: list[str] = field(default_factory=list)
    endorsements: list[str] = field(default_factory=list)
    declassifications: list[str] = field(default_factory=list)
    heuristic_reason: str | None = None


@dataclass
class IFCToolContract:
    tool_name: str
    tool_type: str
    check_mode: str
    sink_scope: str
    args: dict[str, IFCArgumentContract] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    heuristic_reason: str | None = None


@dataclass
class IFCGlobalContract:
    contract_version: str
    generation_mode: str
    benchmark: str
    schema_hash: str
    integrity_lattice: list[str]
    confidentiality_lattice: list[str]
    sink_roles: list[str]
    deny_mark_types: list[str]
    flow_constraint_types: list[str]
    endorsement_types: list[str]
    declassification_types: list[str]
    generated_by: dict[str, Any]
    adapter: dict[str, Any]
    tool_schema_hashes: dict[str, str]
    tools: dict[str, IFCToolContract]
    sink_scope_types: list[str] = field(default_factory=lambda: list(SINK_SCOPES))


def ifc_to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return {key: ifc_to_jsonable(value) for key, value in asdict(obj).items()}
    if isinstance(obj, dict):
        return {key: ifc_to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [ifc_to_jsonable(value) for value in obj]
    return obj


def save_ifc_global_contract(contract: IFCGlobalContract, path: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(ifc_to_jsonable(contract), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def load_ifc_global_contract(path: str) -> IFCGlobalContract:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    validate_ifc_global_contract_schema(data)
    return IFCGlobalContract(
        contract_version=data["contract_version"],
        generation_mode=data["generation_mode"],
        benchmark=data["benchmark"],
        schema_hash=data["schema_hash"],
        integrity_lattice=list(data["integrity_lattice"]),
        confidentiality_lattice=list(data["confidentiality_lattice"]),
        sink_roles=list(data["sink_roles"]),
        sink_scope_types=list(data.get("sink_scope_types", SINK_SCOPES)),
        deny_mark_types=list(data["deny_mark_types"]),
        flow_constraint_types=list(data["flow_constraint_types"]),
        endorsement_types=list(data["endorsement_types"]),
        declassification_types=list(data["declassification_types"]),
        generated_by=dict(data["generated_by"]),
        adapter=dict(data["adapter"]),
        tool_schema_hashes=dict(data["tool_schema_hashes"]),
        tools={name: _tool_from_json(value) for name, value in data["tools"].items()},
    )


def integrity_at_least(label: str, minimum: str) -> bool:
    return INTEGRITY_LATTICE.index(label) <= INTEGRITY_LATTICE.index(minimum)


def confidentiality_at_most(label: str, maximum: str) -> bool:
    return CONFIDENTIALITY_LATTICE.index(label) <= CONFIDENTIALITY_LATTICE.index(maximum)


def validate_ifc_global_contract_schema(data: dict[str, Any]) -> None:
    _reject_legacy_keys(data)
    _reject_forbidden_tokens(data)
    for field_name in (
        "contract_version",
        "generation_mode",
        "benchmark",
        "schema_hash",
        "integrity_lattice",
        "confidentiality_lattice",
        "sink_roles",
        "deny_mark_types",
        "flow_constraint_types",
        "endorsement_types",
        "declassification_types",
        "generated_by",
        "adapter",
        "tool_schema_hashes",
        "tools",
    ):
        if field_name not in data:
            raise ValueError(f"IFC global contract is missing required field '{field_name}'.")
    if data["integrity_lattice"] != INTEGRITY_LATTICE:
        raise ValueError("IFC integrity lattice must match the fixed enum and order.")
    if data["confidentiality_lattice"] != CONFIDENTIALITY_LATTICE:
        raise ValueError("IFC confidentiality lattice must match the fixed enum and order.")
    if data["sink_roles"] != SINK_ROLES:
        raise ValueError("IFC sink roles must match the fixed enum.")
    if data.get("sink_scope_types", SINK_SCOPES) != SINK_SCOPES:
        raise ValueError("IFC sink scopes must match the fixed enum.")
    if data["deny_mark_types"] != DENY_MARK_TYPES:
        raise ValueError("IFC deny marks must match the fixed enum.")
    if data["flow_constraint_types"] != FLOW_CONSTRAINT_TYPES:
        raise ValueError("IFC flow constraints must match the fixed enum.")
    if data["endorsement_types"] != ENDORSEMENT_TYPES:
        raise ValueError("IFC endorsements must match the fixed enum.")
    if data["declassification_types"] != DECLASSIFICATION_TYPES:
        raise ValueError("IFC declassifications must match the fixed enum.")
    if not isinstance(data["tools"], dict) or not data["tools"]:
        raise ValueError("IFC global contract field 'tools' must be a non-empty object.")
    for tool_name, tool in data["tools"].items():
        _validate_tool_contract(tool_name, tool)


def _tool_from_json(data: dict[str, Any]) -> IFCToolContract:
    return IFCToolContract(
        tool_name=data["tool_name"],
        tool_type=data["tool_type"],
        check_mode=data["check_mode"],
        sink_scope=data["sink_scope"],
        args={name: _argument_from_json(value) for name, value in data.get("args", {}).items()},
        output=dict(data.get("output", {})),
        heuristic_reason=data.get("heuristic_reason"),
    )


def _argument_from_json(data: dict[str, Any]) -> IFCArgumentContract:
    return IFCArgumentContract(
        name=data["name"],
        sink_role=data["sink_role"],
        I_min=data["I_min"],
        C_max=data["C_max"],
        deny_marks=list(data.get("deny_marks", [])),
        flow_constraints=list(data.get("flow_constraints", [])),
        endorsements=list(data.get("endorsements", [])),
        declassifications=list(data.get("declassifications", [])),
        heuristic_reason=data.get("heuristic_reason"),
    )


def _validate_tool_contract(tool_name: str, tool: dict[str, Any]) -> None:
    for field_name in ("tool_name", "tool_type", "check_mode", "sink_scope", "args", "output"):
        if field_name not in tool:
            raise ValueError(f"IFC tool contract '{tool_name}' is missing '{field_name}'.")
    if tool["tool_type"] not in TOOL_TYPES:
        raise ValueError(f"IFC tool contract '{tool_name}' has invalid tool_type '{tool['tool_type']}'.")
    if tool["check_mode"] not in CHECK_MODES:
        raise ValueError(f"IFC tool contract '{tool_name}' has invalid check_mode '{tool['check_mode']}'.")
    if tool["sink_scope"] not in SINK_SCOPES:
        raise ValueError(f"IFC tool contract '{tool_name}' has invalid sink_scope '{tool['sink_scope']}'.")
    if not isinstance(tool["args"], dict):
        raise ValueError(f"IFC tool contract '{tool_name}' args must be an object.")
    for argument_name, argument in tool["args"].items():
        _validate_argument_contract(f"{tool_name}.{argument_name}", argument)


def _validate_argument_contract(argument_path: str, argument: dict[str, Any]) -> None:
    for field_name in (
        "name",
        "sink_role",
        "I_min",
        "C_max",
        "deny_marks",
        "flow_constraints",
        "endorsements",
        "declassifications",
    ):
        if field_name not in argument:
            raise ValueError(f"IFC argument contract '{argument_path}' is missing '{field_name}'.")
    if argument["sink_role"] not in SINK_ROLES:
        raise ValueError(f"IFC argument contract '{argument_path}' has invalid sink_role '{argument['sink_role']}'.")
    if argument["I_min"] not in INTEGRITY_LATTICE:
        raise ValueError(f"IFC argument contract '{argument_path}' has invalid I_min '{argument['I_min']}'.")
    if argument["C_max"] not in CONFIDENTIALITY_LATTICE:
        raise ValueError(f"IFC argument contract '{argument_path}' has invalid C_max '{argument['C_max']}'.")
    _validate_list_values(argument_path, "deny_marks", argument["deny_marks"], DENY_MARK_TYPES)
    _validate_list_values(argument_path, "flow_constraints", argument["flow_constraints"], FLOW_CONSTRAINT_TYPES)
    _validate_list_values(argument_path, "endorsements", argument["endorsements"], ENDORSEMENT_TYPES)
    _validate_list_values(argument_path, "declassifications", argument["declassifications"], DECLASSIFICATION_TYPES)


def _validate_list_values(argument_path: str, field_name: str, values: list[str], allowed: list[str]) -> None:
    for value in values:
        if value not in allowed:
            raise ValueError(f"IFC argument contract '{argument_path}' has invalid {field_name} value '{value}'.")


def _reject_legacy_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in LEGACY_KEYS:
                raise ValueError(f"IFC contract must not contain legacy key '{key}'.")
            _reject_legacy_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_legacy_keys(nested)


def _reject_forbidden_tokens(data: dict[str, Any]) -> None:
    text = json.dumps(data, sort_keys=True)
    for token in FORBIDDEN_TOKENS:
        if token in text:
            raise ValueError(f"IFC contract must not contain forbidden token '{token}'.")
