from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any

from pact_drift.contract_schema_l2 import (
    CONTRACT_VERSION,
    DISCHARGE_PROCEDURES,
    FORBIDDEN_ORIGIN_TYPES,
    GENERATION_MODE,
    OBLIGATION_TYPES,
    ROLES,
    TRUST_LATTICE,
    L2ArgumentContract,
    L2GlobalContracts,
    L2ToolContract,
)
from pact_drift.schema_utils import compute_schema_hash, compute_tool_schema_hash

ROLE_DEFAULTS: dict[str, dict[str, Any]] = {
    "target": {
        "tau_min": "DELEGATED",
        "F": ["model_guess", "injected_instruction", "untrusted_raw_text", "unknown_origin"],
        "R": ["authorized_destination", "no_external_redirection"],
        "D": [
            "user_explicit",
            "task_delegation",
            "structured_extraction",
            "trusted_tool_derivation",
            "exact_match_to_authorized_source",
        ],
    },
    "command": {
        "tau_min": "USER",
        "F": ["model_guess", "injected_instruction", "untrusted_raw_text", "unknown_origin"],
        "R": ["authorized_command", "no_policy_override"],
        "D": ["user_explicit", "schema_validated_parse"],
    },
    "credential": {
        "tau_min": "TRUSTED",
        "F": ["model_guess", "injected_instruction", "credential_leakage", "unknown_origin"],
        "R": ["authorized_credential_use"],
        "D": ["user_explicit", "exact_match_to_authorized_source"],
    },
    "content": {
        "tau_min": "TOOL_OUTPUT",
        "F": ["injected_instruction", "unknown_origin"],
        "R": ["non_instructional_content", "task_relevance"],
        "D": [
            "user_explicit",
            "task_delegation",
            "structured_extraction",
            "exact_match_to_authorized_source",
            "schema_validated_parse",
        ],
    },
    "selector": {
        "tau_min": "TOOL_OUTPUT",
        "F": ["model_guess", "injected_instruction", "unknown_origin"],
        "R": ["authorized_object_selection", "task_relevance"],
        "D": [
            "user_explicit",
            "task_delegation",
            "exact_match_to_authorized_source",
            "trusted_tool_derivation",
            "schema_validated_parse",
        ],
    },
    "control": {
        "tau_min": "DELEGATED",
        "F": ["model_guess", "injected_instruction", "default_without_authorization", "unknown_origin"],
        "R": ["authorized_control_value", "structured_field_required"],
        "D": [
            "user_explicit",
            "task_delegation",
            "structured_extraction",
            "exact_match_to_authorized_source",
            "schema_validated_parse",
        ],
    },
}

ACTION_MARKERS = (
    "send",
    "transfer",
    "pay",
    "delete",
    "update",
    "create",
    "book",
    "schedule",
    "write",
    "execute",
    "cancel",
    "remove",
    "modify",
)
SENSITIVE_MARKERS = (
    "iban",
    "balance",
    "transaction",
    "account",
    "file",
    "email",
    "contact",
    "profile",
    "user_info",
    "inbox",
    "calendar",
)
TARGET_MARKERS = (
    "recipient",
    "to",
    "receiver",
    "destination",
    "account",
    "iban",
    "url",
    "path",
    "file_path",
    "channel",
    "attendee",
    "email",
    "address",
)
COMMAND_MARKERS = ("command", "mutation", "instruction", "script", "code", "sql", "shell")
CREDENTIAL_MARKERS = ("token", "api_key", "apikey", "password", "secret", "credential", "auth")
SELECTOR_MARKERS = ("id", "name", "query", "filter", "index", "number", "n")
CONTROL_MARKERS = ("amount", "date", "time", "mode", "overwrite", "limit", "count", "n", "recurring", "enabled", "status")
CONTENT_MARKERS = ("body", "message", "subject", "description", "summary", "content", "text", "note", "title")


def infer_tool_type(schema: dict[str, Any]) -> tuple[str, str, str]:
    name = str(schema.get("name", ""))
    haystack = _schema_haystack(schema)
    if _contains_any(haystack, ACTION_MARKERS):
        return "ACTION", "full", f"'{name}' or its description indicates state-changing behavior."
    if _contains_any(haystack, SENSITIVE_MARKERS):
        return "READ_SENSITIVE", "control_check_and_track", f"'{name}' or its description indicates sensitive reads."
    return "READ_LOW", "track_only", f"'{name}' does not match action or sensitive-read heuristics."


def infer_argument_role(tool_schema: dict[str, Any], arg_name: str, arg_schema: dict[str, Any]) -> tuple[str, str]:
    tool_type, _, _ = infer_tool_type(tool_schema)
    name = arg_name.lower()
    description = str(arg_schema.get("description", "")).lower()
    arg_haystack = f"{name} {description}"
    if _contains_any(arg_haystack, CREDENTIAL_MARKERS):
        return "credential", f"'{arg_name}' names an authentication or secret-bearing value."
    if _contains_any(arg_haystack, CONTROL_MARKERS):
        return "control", f"'{arg_name}' controls amount, time, mode, or behavior."
    if _contains_any(arg_haystack, COMMAND_MARKERS) and not _is_read_low_search_query(tool_schema, tool_type, name):
        return "command", f"'{arg_name}' can encode executable instructions or mutations."
    if _contains_any(arg_haystack, TARGET_MARKERS) and not _is_read_low_search_query(tool_schema, tool_type, name):
        return "target", f"'{arg_name}' identifies an authority-bearing destination or object."
    if _contains_any(arg_haystack, SELECTOR_MARKERS):
        return "selector", f"'{arg_name}' selects an object or subset."
    if _contains_any(arg_haystack, CONTENT_MARKERS):
        return "content", f"'{arg_name}' carries user-visible or tool-visible content."
    return "content", f"'{arg_name}' did not match stricter role heuristics; defaulting to content."


def generate_global_tool_contracts_l2(tool_schemas: list[dict[str, Any]]) -> L2GlobalContracts:
    ordered_schemas = sorted(tool_schemas, key=lambda schema: schema["name"])
    tools = {schema["name"]: _generate_tool_contract(schema) for schema in ordered_schemas}
    return L2GlobalContracts(
        contract_version=CONTRACT_VERSION,
        generation_mode=GENERATION_MODE,
        schema_hash=compute_schema_hash(ordered_schemas),
        trust_lattice=list(TRUST_LATTICE),
        roles=list(ROLES),
        forbidden_origin_types=list(FORBIDDEN_ORIGIN_TYPES),
        obligation_types=list(OBLIGATION_TYPES),
        discharge_procedures=list(DISCHARGE_PROCEDURES),
        generated_by={
            "mode": GENERATION_MODE,
            "model": "none",
            "notes": "Generated by deterministic heuristic. Review before freezing.",
        },
        tools=tools,
        tool_schema_hashes={schema["name"]: compute_tool_schema_hash(schema) for schema in ordered_schemas},
    )


def summarize_l2_contracts(contracts: L2GlobalContracts) -> dict[str, Any]:
    tool_type_counts = Counter(tool.tool_type for tool in contracts.tools.values())
    role_counts = Counter(argument.role for tool in contracts.tools.values() for argument in tool.args.values())
    return {
        "tool_count": len(contracts.tools),
        "ACTION": tool_type_counts["ACTION"],
        "READ_SENSITIVE": tool_type_counts["READ_SENSITIVE"],
        "READ_LOW": tool_type_counts["READ_LOW"],
        "argument_count": sum(len(tool.args) for tool in contracts.tools.values()),
        "roles": {role: role_counts[role] for role in ROLES},
    }


def _generate_tool_contract(schema: dict[str, Any]) -> L2ToolContract:
    tool_type, check_mode, tool_reason = infer_tool_type(schema)
    properties = schema.get("parameters", {}).get("properties", {})
    args = {
        arg_name: _generate_argument_contract(schema, arg_name, arg_schema)
        for arg_name, arg_schema in sorted(properties.items())
    }
    output = {
        "raw_output_trust": "TOOL_OUTPUT",
        "propagate_input_origins": False,
        "requires_structured_extraction": False,
    }
    contract = L2ToolContract(
        tool_name=schema["name"],
        tool_type=tool_type,
        check_mode=check_mode,
        args=args,
        output=output,
        heuristic_reason=tool_reason,
    )
    _apply_special_rules(contract)
    return contract


def _generate_argument_contract(tool_schema: dict[str, Any], arg_name: str, arg_schema: dict[str, Any]) -> L2ArgumentContract:
    role, reason = infer_argument_role(tool_schema, arg_name, arg_schema)
    defaults = deepcopy(ROLE_DEFAULTS[role])
    if role == "content" and infer_tool_type(tool_schema)[0] == "ACTION":
        _append_unique(defaults["R"], "no_policy_override")
    return L2ArgumentContract(
        name=arg_name,
        role=role,
        tau_min=defaults["tau_min"],
        F=list(defaults["F"]),
        R=list(defaults["R"]),
        D=list(defaults["D"]),
        heuristic_reason=reason,
    )


def _apply_special_rules(contract: L2ToolContract) -> None:
    if _is_transaction_sensitive_tool(contract.tool_name):
        contract.tool_type = "READ_SENSITIVE" if contract.tool_type != "ACTION" else contract.tool_type
        contract.check_mode = "control_check_and_track" if contract.tool_type == "READ_SENSITIVE" else contract.check_mode
    if contract.tool_name == "send_money":
        _force_role(contract, "recipient", "target", "recipient determines the destination of a money transfer")
        _force_role(contract, "amount", "control", "amount controls the transferred financial value")
        _force_role(contract, "subject", "content", "subject carries transfer memo content")
        _force_role(contract, "date", "control", "date controls when the transfer is executed")
        _append_arg_unique(contract, "recipient", "F", "unrequested_transaction_history")
        _append_arg_unique(contract, "amount", "F", "unrequested_transaction_history")
        _append_arg_unique(contract, "date", "F", "default_without_authorization")
        _append_arg_unique(contract, "subject", "R", "task_relevance")
    if contract.tool_name == "update_scheduled_transaction":
        _force_role(contract, "id", "selector", "id selects the scheduled transaction to update")
        _force_role(contract, "date", "control", "date controls scheduled execution")
        _force_role(contract, "amount", "control", "amount controls scheduled financial value")
        _force_role(contract, "recipient", "target", "recipient is the updated transfer destination")
    if contract.tool_name == "get_iban":
        contract.output["propagate_input_origins"] = True
    if contract.tool_name == "read_file":
        contract.output["raw_output_trust"] = "EXTERNAL"
        contract.output["requires_structured_extraction"] = True


def _force_role(contract: L2ToolContract, arg_name: str, role: str, reason: str) -> None:
    if arg_name not in contract.args:
        return
    defaults = deepcopy(ROLE_DEFAULTS[role])
    contract.args[arg_name] = L2ArgumentContract(
        name=arg_name,
        role=role,
        tau_min=defaults["tau_min"],
        F=list(defaults["F"]),
        R=list(defaults["R"]),
        D=list(defaults["D"]),
        heuristic_reason=reason,
    )


def _append_arg_unique(contract: L2ToolContract, arg_name: str, field_name: str, value: str) -> None:
    if arg_name in contract.args:
        _append_unique(getattr(contract.args[arg_name], field_name), value)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _schema_haystack(schema: dict[str, Any]) -> str:
    return f"{schema.get('name', '')} {schema.get('description', '')}".lower()


def _is_read_low_search_query(tool_schema: dict[str, Any], tool_type: str, arg_name: str) -> bool:
    return tool_type == "READ_LOW" and arg_name == "query" and "search" in str(tool_schema.get("name", "")).lower()


def _is_transaction_sensitive_tool(tool_name: str) -> bool:
    lower_name = tool_name.lower()
    return any(marker in lower_name for marker in ("transaction", "balance", "account"))
