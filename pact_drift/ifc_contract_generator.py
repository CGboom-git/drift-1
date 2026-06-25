from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any

from pact_drift.ifc_contract_schema import (
    CONFIDENTIALITY_LATTICE,
    CONTRACT_VERSION,
    DECLASSIFICATION_TYPES,
    DENY_MARK_TYPES,
    ENDORSEMENT_TYPES,
    FLOW_CONSTRAINT_TYPES,
    GENERATION_MODE,
    INTEGRITY_LATTICE,
    SINK_ROLES,
    IFCArgumentContract,
    IFCGlobalContract,
    IFCToolContract,
)
from pact_drift.schema_utils import compute_schema_hash, compute_tool_schema_hash

ROLE_DEFAULTS: dict[str, dict[str, Any]] = {
    "target": {
        "I_min": "DELEGATED",
        "C_max": "USER_PRIVATE",
        "deny_marks": ["model_inferred_unverified", "injected_instruction", "raw_external_content", "unknown_origin"],
        "flow_constraints": ["authorized_destination", "no_external_redirection"],
        "endorsements": [
            "user_explicit",
            "task_delegation",
            "structured_extraction",
            "trusted_tool_derivation",
            "exact_match_to_authorized_source",
            "source_object_binding",
        ],
        "declassifications": ["destination_scope_match"],
    },
    "command": {
        "I_min": "USER",
        "C_max": "INTERNAL",
        "deny_marks": [
            "model_inferred_unverified",
            "injected_instruction",
            "raw_external_content",
            "policy_override_content",
            "unknown_origin",
        ],
        "flow_constraints": ["authorized_command", "no_policy_override"],
        "endorsements": ["user_explicit", "schema_validated_parse", "deterministic_transform"],
        "declassifications": [],
    },
    "credential": {
        "I_min": "TRUSTED",
        "C_max": "SECRET",
        "deny_marks": ["model_inferred_unverified", "injected_instruction", "credential_or_secret", "unknown_origin"],
        "flow_constraints": ["authorized_credential_use"],
        "endorsements": ["user_explicit", "exact_match_to_authorized_source", "source_object_binding"],
        "declassifications": [],
    },
    "content": {
        "I_min": "TOOL_OUTPUT",
        "C_max": "USER_PRIVATE",
        "deny_marks": ["injected_instruction", "policy_override_content", "unknown_origin"],
        "flow_constraints": ["non_instructional_content", "task_relevance"],
        "endorsements": [
            "user_explicit",
            "task_delegation",
            "structured_extraction",
            "schema_validated_parse",
            "exact_match_to_authorized_source",
        ],
        "declassifications": [
            "explicit_output_delegation",
            "content_minimization",
            "task_relevant_private_output",
            "schema_validated_export",
            "redaction_or_abstraction",
        ],
    },
    "selector": {
        "I_min": "TOOL_OUTPUT",
        "C_max": "USER_PRIVATE",
        "deny_marks": ["model_inferred_unverified", "injected_instruction", "unknown_origin", "stale_or_ambiguous_source"],
        "flow_constraints": ["authorized_object_selection", "task_relevance"],
        "endorsements": [
            "user_explicit",
            "task_delegation",
            "exact_match_to_authorized_source",
            "trusted_tool_derivation",
            "schema_validated_parse",
            "source_object_binding",
        ],
        "declassifications": [],
    },
    "control": {
        "I_min": "DELEGATED",
        "C_max": "SENSITIVE",
        "deny_marks": ["model_inferred_unverified", "injected_instruction", "default_without_authorization", "unknown_origin"],
        "flow_constraints": ["authorized_control_value", "structured_source_required"],
        "endorsements": [
            "user_explicit",
            "task_delegation",
            "structured_extraction",
            "exact_match_to_authorized_source",
            "schema_validated_parse",
            "deterministic_transform",
        ],
        "declassifications": [],
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
    "reserve",
    "schedule",
    "write",
    "execute",
    "cancel",
    "remove",
    "modify",
    "add",
    "invite",
    "share",
    "append",
    "post",
)
SENSITIVE_MARKERS = (
    "email",
    "file",
    "inbox",
    "calendar",
    "contact",
    "profile",
    "user_info",
    "account",
    "balance",
    "transaction",
    "message",
    "channel",
    "document",
    "webpage",
)
TARGET_MARKERS = (
    "recipient",
    "receiver",
    "to",
    "destination",
    "account",
    "iban",
    "url",
    "path",
    "file_id",
    "file_path",
    "channel",
    "attendee",
    "participant",
    "participants",
    "email",
    "address",
    "user",
)
COMMAND_MARKERS = ("command", "mutation", "instruction", "script", "code", "sql", "shell")
CREDENTIAL_MARKERS = ("token", "api_key", "apikey", "password", "secret", "credential", "auth")
SELECTOR_MARKERS = ("id", "name", "query", "filter", "index", "number", "n", "city", "company", "hotel", "restaurant")
CONTROL_MARKERS = (
    "amount",
    "date",
    "time",
    "start_time",
    "end_time",
    "mode",
    "overwrite",
    "limit",
    "count",
    "recurring",
    "enabled",
    "status",
    "permission",
)
CONTENT_MARKERS = ("body", "message", "subject", "description", "summary", "content", "text", "note", "title")


def infer_tool_type(schema: dict[str, Any]) -> tuple[str, str, str]:
    name = str(schema.get("name", ""))
    haystack = _schema_haystack(schema)
    if _contains_any(haystack, ACTION_MARKERS):
        return "ACTION", "full", f"'{name}' or its description indicates state-changing behavior."
    if _contains_any(haystack, SENSITIVE_MARKERS):
        return "READ_SENSITIVE", "control_check_and_track", f"'{name}' or its description indicates sensitive reads."
    return "READ_LOW", "track_only", f"'{name}' does not match action or sensitive-read heuristics."


def infer_sink_scope(schema: dict[str, Any]) -> tuple[str, str]:
    name = str(schema.get("name", "")).lower()
    haystack = _schema_haystack(schema)
    if _contains_any(haystack, ("password", "credential", "secret", "token", "api_key", "apikey")):
        return "credential", "Tool handles credential or secret material."
    if _contains_any(haystack, ("money", "transaction", "balance", "iban", "payment")):
        return "financial", "Tool belongs to financial data or financial actions."
    if _contains_any(haystack, ("email", "slack", "message", "dm", "channel")):
        return "messaging", "Tool exchanges messages or channel content."
    if _contains_any(haystack, ("calendar", "event", "participants", "attendee")):
        return "calendar", "Tool handles calendar events or participants."
    if _contains_any(haystack, ("post_webpage", "publish", "public")):
        return "public", "Tool publishes content to a public sink."
    if _contains_any(haystack, ("share", "invite", "external user")):
        return "external", "Tool shares data with an external principal."
    if _contains_any(name, ("file", "document", "workspace")):
        return "workspace", "Tool acts on workspace or file-system objects."
    return "none", "Tool has no obvious output sink scope."


def infer_argument_sink_role(tool_schema: dict[str, Any], arg_name: str, arg_schema: dict[str, Any]) -> tuple[str, str]:
    tool_type, _, _ = infer_tool_type(tool_schema)
    name = arg_name.lower()
    description = str(arg_schema.get("description", "")).lower()
    arg_haystack = f"{name} {description}"
    if _contains_any(arg_haystack, CREDENTIAL_MARKERS):
        return "credential", f"'{arg_name}' names a credential or secret-bearing value."
    if _contains_any(arg_haystack, CONTROL_MARKERS):
        return "control", f"'{arg_name}' controls amount, time, mode, permission, or status."
    if _contains_any(arg_haystack, COMMAND_MARKERS) and not _is_read_low_search_query(tool_schema, tool_type, name):
        return "command", f"'{arg_name}' can encode executable instructions or mutations."
    if _contains_any(arg_haystack, TARGET_MARKERS) and not _is_read_low_search_query(tool_schema, tool_type, name):
        return "target", f"'{arg_name}' identifies a destination, principal, or object."
    if _contains_any(arg_haystack, SELECTOR_MARKERS):
        return "selector", f"'{arg_name}' selects an object or subset."
    if _contains_any(arg_haystack, CONTENT_MARKERS):
        return "content", f"'{arg_name}' carries content payload."
    return "content", f"fallback_to_content: '{arg_name}' did not match stricter IFC sink-role heuristics."


def generate_ifc_global_contract(
    tool_schemas: list[dict[str, Any]],
    benchmark: str,
    adapter_metadata: dict[str, Any],
) -> IFCGlobalContract:
    ordered_schemas = sorted(tool_schemas, key=lambda schema: schema["name"])
    tools = {schema["name"]: _generate_tool_contract(schema) for schema in ordered_schemas}
    return IFCGlobalContract(
        contract_version=CONTRACT_VERSION,
        generation_mode=GENERATION_MODE,
        benchmark=benchmark,
        schema_hash=compute_schema_hash(ordered_schemas),
        integrity_lattice=list(INTEGRITY_LATTICE),
        confidentiality_lattice=list(CONFIDENTIALITY_LATTICE),
        sink_roles=list(SINK_ROLES),
        deny_mark_types=list(DENY_MARK_TYPES),
        flow_constraint_types=list(FLOW_CONSTRAINT_TYPES),
        endorsement_types=list(ENDORSEMENT_TYPES),
        declassification_types=list(DECLASSIFICATION_TYPES),
        generated_by={
            "mode": GENERATION_MODE,
            "model": "none",
            "notes": "Generated by deterministic heuristic. Review before freezing.",
        },
        adapter=adapter_metadata,
        tool_schema_hashes={schema["name"]: compute_tool_schema_hash(schema) for schema in ordered_schemas},
        tools=tools,
    )


def summarize_ifc_contract(contract: IFCGlobalContract) -> dict[str, Any]:
    tool_type_counts = Counter(tool.tool_type for tool in contract.tools.values())
    role_counts = Counter(argument.sink_role for tool in contract.tools.values() for argument in tool.args.values())
    scope_counts = Counter(tool.sink_scope for tool in contract.tools.values())
    return {
        "tool_count": len(contract.tools),
        "ACTION": tool_type_counts["ACTION"],
        "READ_SENSITIVE": tool_type_counts["READ_SENSITIVE"],
        "READ_LOW": tool_type_counts["READ_LOW"],
        "argument_count": sum(len(tool.args) for tool in contract.tools.values()),
        "sink_roles": {role: role_counts[role] for role in SINK_ROLES},
        "sink_scopes": dict(sorted(scope_counts.items())),
    }


def _generate_tool_contract(schema: dict[str, Any]) -> IFCToolContract:
    tool_type, check_mode, tool_reason = infer_tool_type(schema)
    sink_scope, scope_reason = infer_sink_scope(schema)
    properties = schema.get("parameters", {}).get("properties", {})
    contract = IFCToolContract(
        tool_name=schema["name"],
        tool_type=tool_type,
        check_mode=check_mode,
        sink_scope=sink_scope,
        args={
            arg_name: _generate_argument_contract(schema, arg_name, arg_schema, sink_scope)
            for arg_name, arg_schema in sorted(properties.items())
        },
        output=_default_output_policy(schema["name"], tool_type, sink_scope),
        heuristic_reason=f"{tool_reason} {scope_reason}",
    )
    _apply_special_rules(contract)
    return contract


def _generate_argument_contract(
    tool_schema: dict[str, Any],
    arg_name: str,
    arg_schema: dict[str, Any],
    sink_scope: str,
) -> IFCArgumentContract:
    sink_role, reason = infer_argument_sink_role(tool_schema, arg_name, arg_schema)
    defaults = deepcopy(ROLE_DEFAULTS[sink_role])
    contract = IFCArgumentContract(
        name=arg_name,
        sink_role=sink_role,
        I_min=defaults["I_min"],
        C_max=defaults["C_max"],
        deny_marks=list(defaults["deny_marks"]),
        flow_constraints=list(defaults["flow_constraints"]),
        endorsements=list(defaults["endorsements"]),
        declassifications=list(defaults["declassifications"]),
        heuristic_reason=reason,
    )
    _tune_argument_for_scope(contract, sink_scope)
    return contract


def _default_output_policy(tool_name: str, tool_type: str, sink_scope: str) -> dict[str, Any]:
    c_label_by_scope = {
        "financial": "SENSITIVE",
        "credential": "SECRET",
        "messaging": "USER_PRIVATE",
        "calendar": "USER_PRIVATE",
        "workspace": "USER_PRIVATE",
        "external": "USER_PRIVATE",
        "public": "PUBLIC",
        "internal": "INTERNAL",
        "none": "INTERNAL",
    }
    output = {
        "I_label": "TRUSTED" if tool_type == "ACTION" else "TOOL_OUTPUT",
        "C_label": c_label_by_scope.get(sink_scope, "INTERNAL"),
        "propagate_input_origins": False,
        "raw_output_trust": "TOOL_OUTPUT",
        "requires_structured_extraction": False,
    }
    if tool_name == "read_file":
        output["I_label"] = "EXTERNAL"
        output["raw_output_trust"] = "EXTERNAL"
        output["requires_structured_extraction"] = True
    if tool_name == "get_iban":
        output["propagate_input_origins"] = True
    return output


def _tune_argument_for_scope(argument: IFCArgumentContract, sink_scope: str) -> None:
    if sink_scope == "public" and argument.sink_role == "content":
        argument.C_max = "PUBLIC"
        _append_unique(argument.flow_constraints, "no_private_to_public_sink")
        _append_unique(argument.flow_constraints, "minimal_disclosure")
    if sink_scope == "messaging":
        if argument.sink_role == "target":
            _append_unique(argument.flow_constraints, "destination_scope_match")
        if argument.sink_role == "content":
            _append_unique(argument.flow_constraints, "destination_scope_match")
            _append_unique(argument.flow_constraints, "minimal_disclosure")
    if sink_scope == "financial" and argument.sink_role in {"target", "control"}:
        argument.I_min = "DELEGATED"
        _append_unique(argument.deny_marks, "unauthorized_tool_output")
    if sink_scope == "credential" or argument.sink_role == "credential":
        argument.C_max = "SECRET"


def _apply_special_rules(contract: IFCToolContract) -> None:
    if contract.tool_name == "send_money":
        contract.sink_scope = "financial"
        _force_role(contract, "recipient", "target", "recipient determines the destination of a money transfer.")
        _force_role(contract, "amount", "control", "amount controls the magnitude of a money transfer.")
        _force_role(contract, "subject", "content", "subject carries transfer memo content.")
        _force_role(contract, "date", "control", "date controls when the transfer is executed.")
    if contract.tool_name == "update_scheduled_transaction":
        contract.sink_scope = "financial"
        _force_role(contract, "id", "selector", "id selects the scheduled transaction to update.")
        _force_role(contract, "date", "control", "date controls scheduled execution.")
        _force_role(contract, "amount", "control", "amount controls scheduled financial value.")
        _force_role(contract, "recipient", "target", "recipient is the updated transfer destination.")
    if contract.tool_name in {"create_file", "append_to_file"}:
        contract.sink_scope = "workspace"
        if "content" in contract.args:
            contract.args["content"].C_max = "USER_PRIVATE"
    if contract.tool_name == "post_webpage":
        contract.sink_scope = "public"
        _force_role(contract, "url", "target", "url identifies the public publishing destination.")
        if "content" in contract.args:
            contract.args["content"].C_max = "PUBLIC"
            _append_unique(contract.args["content"].flow_constraints, "no_private_to_public_sink")
            _append_unique(contract.args["content"].flow_constraints, "minimal_disclosure")
    if contract.tool_name == "share_file":
        contract.sink_scope = "external"
        if "file_id" in contract.args:
            _append_unique(contract.args["file_id"].flow_constraints, "object_confidentiality_check")
            _append_unique(contract.args["file_id"].flow_constraints, "destination_scope_match")
            _append_unique(contract.args["file_id"].declassifications, "object_share_authorization")
            _append_unique(contract.args["file_id"].declassifications, "destination_scope_match")
    for argument in contract.args.values():
        _tune_argument_for_scope(argument, contract.sink_scope)
    contract.output = _default_output_policy(contract.tool_name, contract.tool_type, contract.sink_scope)


def _force_role(contract: IFCToolContract, arg_name: str, sink_role: str, reason: str) -> None:
    if arg_name not in contract.args:
        return
    defaults = deepcopy(ROLE_DEFAULTS[sink_role])
    contract.args[arg_name] = IFCArgumentContract(
        name=arg_name,
        sink_role=sink_role,
        I_min=defaults["I_min"],
        C_max=defaults["C_max"],
        deny_marks=list(defaults["deny_marks"]),
        flow_constraints=list(defaults["flow_constraints"]),
        endorsements=list(defaults["endorsements"]),
        declassifications=list(defaults["declassifications"]),
        heuristic_reason=reason,
    )


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _schema_haystack(schema: dict[str, Any]) -> str:
    return f"{schema.get('name', '')} {schema.get('description', '')}".lower()


def _is_read_low_search_query(tool_schema: dict[str, Any], tool_type: str, arg_name: str) -> bool:
    return tool_type == "READ_LOW" and arg_name == "query" and "search" in str(tool_schema.get("name", "")).lower()


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)
