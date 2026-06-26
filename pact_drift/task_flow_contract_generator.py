from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

try:
    from json_repair import repair_json
except ImportError:  # pragma: no cover - exercised only in minimal local environments.
    def repair_json(value: str) -> str:
        return value

from pact_drift.ifc_contract_schema import IFCGlobalContract, ifc_to_jsonable
from pact_drift.task_flow_contract import (
    TASK_CONTRACT_VERSION,
    FlowBinding,
    TaskFlowContract,
    UnresolvedBinding,
    task_flow_contract_from_json,
)
from prompts import IFC_TASK_FLOW_CONTRACT_PROMPT


@dataclass
class DelegatedSource:
    tool_name: str
    source_path_prefix: str
    source_kind: str
    I_label: str
    C_label: str
    authorized_by_task: bool
    reason: str


@dataclass
class CandidateSourceField:
    source_path: str
    source_role: str
    field_name: str
    I_after: str
    C_label: str
    endorsements: list[str] = field(default_factory=list)
    reason: str = ""


def generate_task_flow_contract(
    user_query: str,
    initial_function_trajectory: list[str],
    tool_schemas: list[dict[str, Any]],
    global_contract: IFCGlobalContract,
    client: Any | None = None,
    model: str | None = None,
) -> TaskFlowContract:
    if client is not None:
        generated = _generate_with_client(
            user_query,
            initial_function_trajectory,
            tool_schemas,
            global_contract,
            client,
            model,
        )
        if generated is not None:
            return generated
    return deterministic_task_flow_contract(
        user_query,
        initial_function_trajectory,
        global_contract,
        tool_schemas=tool_schemas,
    )


def deterministic_task_flow_contract(
    user_query: str,
    initial_function_trajectory: list[str],
    global_contract: IFCGlobalContract,
    tool_schemas: list[dict[str, Any]] | None = None,
) -> TaskFlowContract:
    explicit_fields = extract_explicit_user_fields(user_query)
    flow_bindings: dict[str, list[FlowBinding]] = {}
    unresolved: list[UnresolvedBinding] = []
    schemas = tool_schemas or []
    delegated_sources = collect_delegated_sources(
        user_query=user_query,
        initial_function_trajectory=initial_function_trajectory,
        global_contract=global_contract,
        tool_schemas=schemas,
    )
    candidate_fields = collect_candidate_source_fields(
        delegated_sources=delegated_sources,
        initial_function_trajectory=initial_function_trajectory,
        global_contract=global_contract,
        tool_schemas=schemas,
    )
    for tool_name in initial_function_trajectory:
        tool = global_contract.tools.get(tool_name)
        if not tool or tool.tool_type != "ACTION":
            continue
        for argument_name, argument_contract in tool.args.items():
            sink = f"{tool_name}.{argument_name}"
            candidate = find_unique_candidate_for_sink(sink, argument_contract, candidate_fields)
            if candidate is not None and _candidate_satisfies_global_requirements(argument_contract, candidate):
                add_binding_from_candidate(global_contract, flow_bindings, sink, candidate)
                continue
            explicit_value = explicit_fields.get(argument_name)
            if explicit_value is not None:
                _add_binding(
                    global_contract,
                    flow_bindings,
                    sink,
                    f"user.explicit.{argument_name}",
                    "USER",
                    argument_contract.C_max,
                    "argument value was explicitly present in the original user query",
                    endorsements=_explicit_endorsements(argument_contract.endorsements),
                )
            else:
                unresolved.append(
                    UnresolvedBinding(
                        sink=sink,
                        required_constraints=list(argument_contract.flow_constraints),
                        reason="No task-authorized provenance source was inferred by the deterministic fallback.",
                    )
                )
    contract = TaskFlowContract(
        task_contract_version=TASK_CONTRACT_VERSION,
        task_type=_task_type(initial_function_trajectory, global_contract),
        allowed_trajectory=list(initial_function_trajectory),
        opportunistic_read_policy={
            "READ_LOW": "allow_and_track",
            "READ_SENSITIVE": "allow_and_quarantine_unless_task_delegated",
            "output_can_flow_to_action_by_default": False,
        },
        source_delegations=_source_delegations_from_candidates(candidate_fields),
        flow_bindings=flow_bindings,
        unresolved_bindings=unresolved,
    )
    task_flow_contract_from_json(contract.to_json(), global_contract)
    return contract


def extract_explicit_user_fields(user_query: str) -> dict[str, Any]:
    """Conservatively extract authority-bearing values explicitly present in the user query."""
    fields: dict[str, Any] = {}
    query = user_query.strip()
    lower = query.lower()
    amount_match = re.search(r"(?i)(?:[$]\s*\d+(?:\.\d+)?|\b\d+(?:\.\d+)?\s*(?:dollars?|usd|eur|euros?|pounds?|gbp)\b)", query)
    if amount_match:
        number = re.search(r"\d+(?:\.\d+)?", amount_match.group(0))
        fields["amount"] = number.group(0) if number else amount_match.group(0).strip()
    date_match = re.search(
        r"(?i)\b(?:today|tomorrow|tonight|next\s+\w+|\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{2,4}|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b(?:\s+\d{1,2}(?:st|nd|rd|th)?)?",
        query,
    )
    if date_match:
        fields["date"] = date_match.group(0).strip()
    recipient_match = re.search(r"\b(?:[Pp]ay|[Ss]end|[Tt]ransfer)\s+(?:money\s+)?(?:to\s+)?([A-Z][A-Za-z0-9_.@-]*(?:\s+[A-Z][A-Za-z0-9_.@-]*){0,3})", query)
    if recipient_match:
        candidate = recipient_match.group(1).strip()
        candidate = re.sub(r"\s+\d.*$", "", candidate).strip()
        if candidate:
            fields["recipient"] = candidate
            fields["to"] = candidate
    quoted = re.search(r"['\"]([^'\"]+)['\"]", query)
    if quoted:
        fields["subject"] = quoted.group(1)
        fields["body"] = quoted.group(1)
        fields["content"] = quoted.group(1)
    channel_match = re.search(r"(?i)\b(?:channel|room)\s+([#@]?[A-Za-z0-9_.-]+)", query)
    if channel_match:
        fields["channel"] = channel_match.group(1)
    file_id_match = re.search(r"(?i)\b(?:file[_\s-]?id)\s*[:=]?\s*([A-Za-z0-9_.-]+)", query)
    if file_id_match:
        fields["file_id"] = file_id_match.group(1)
    url_match = re.search(r"https?://\S+", query)
    if url_match:
        fields["url"] = url_match.group(0).rstrip(".,)")
    if "participants" in lower or "attendees" in lower:
        participants = re.findall(r"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?\b", query)
        if participants:
            fields["participants"] = participants
    return fields


def summarize_task_flow_contract(contract: TaskFlowContract | None) -> dict[str, Any]:
    if contract is None:
        return {}
    compact_bindings = {}
    for sink, bindings in contract.flow_bindings.items():
        compact_bindings[sink] = [
            {
                "source_path": binding.source_path,
                "I_after": binding.I_after,
                "C_label": binding.C_label,
                "satisfies": list(binding.satisfies),
                "reason": binding.reason,
            }
            for binding in bindings
        ]
    return {
        "task_contract_version": contract.task_contract_version,
        "task_type": contract.task_type,
        "allowed_trajectory": contract.allowed_trajectory,
        "flow_bindings": compact_bindings,
        "unresolved_bindings": [
            {
                "sink": item.sink,
                "required_constraints": list(item.required_constraints),
                "reason": item.reason,
                "policy": item.policy,
            }
            for item in contract.unresolved_bindings
        ],
        "opportunistic_read_policy": contract.opportunistic_read_policy,
    }


def _generate_with_client(
    user_query: str,
    initial_function_trajectory: list[str],
    tool_schemas: list[dict[str, Any]],
    global_contract: IFCGlobalContract,
    client: Any,
    model: str | None,
) -> TaskFlowContract | None:
    relevant_tools = _relevant_tool_schemas(tool_schemas, initial_function_trajectory)
    global_subset = {
        name: ifc_to_jsonable(global_contract.tools[name])
        for name in initial_function_trajectory
        if name in global_contract.tools
    }
    user_prompt = json.dumps(
        {
            "original_user_task": user_query,
            "planned_function_trajectory": initial_function_trajectory,
            "tool_schemas": relevant_tools,
            "ifc_global_contract_subset": global_subset,
            "model": model or "",
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    response = client.llm_run(IFC_TASK_FLOW_CONTRACT_PROMPT, user_prompt, name="ifc_task_flow_contract")
    if not response or "FAILED GENERATION" in response:
        return None
    try:
        repaired = repair_json(response)
        data = json.loads(repaired)
        return task_flow_contract_from_json(data, global_contract)
    except Exception:
        return None


def _add_binding(
    global_contract: IFCGlobalContract,
    flow_bindings: dict[str, list[FlowBinding]],
    sink: str,
    source_path: str,
    i_after: str,
    c_label: str,
    reason: str,
    endorsements: list[str] | None = None,
) -> None:
    tool_name, argument_name = sink.split(".", 1)
    argument_contract = global_contract.tools[tool_name].args[argument_name]
    flow_bindings.setdefault(sink, []).append(
        FlowBinding(
            source_path=source_path,
            sink=sink,
            I_after=i_after,
            C_label=c_label,
            satisfies=list(argument_contract.flow_constraints),
            endorsements=list(endorsements) if endorsements is not None else list(argument_contract.endorsements),
            declassifications=[],
            reason=reason,
        )
    )


GENERIC_OUTPUT_FIELD_ALIASES = {
    "file": ["content", "summary", "title", "subject", "amount", "date", "due_date", "name"],
    "email": ["email_id", "sender", "recipient", "subject", "body", "date"],
    "message": ["sender", "channel", "message", "timestamp"],
    "calendar": ["event_id", "title", "participants", "start_time", "end_time", "date", "location"],
    "travel": ["name", "city", "address", "price", "rating", "date", "time"],
    "generic": ["id", "name", "title", "description", "content", "date", "time"],
}

ROLE_KEYWORDS = {
    "credential": ["password", "token", "secret", "api_key", "credential", "auth"],
    "content": ["body", "message", "subject", "description", "summary", "content", "text", "note", "title"],
    "control": ["amount", "price", "date", "time", "start_time", "end_time", "limit", "count", "status", "permission", "due_date"],
    "target": ["recipient", "receiver", "to", "email", "user", "participant", "attendee", "channel", "file_id", "account", "iban", "url", "address", "destination"],
    "selector": ["query", "name", "id", "filter", "city", "hotel", "restaurant", "company"],
    "command": ["command", "script", "code", "mutation", "instruction"],
}

ROLE_PRIORITY = ["credential", "content", "control", "target", "selector", "command"]

COMPATIBLE_ROLES = {
    "target": {"target", "selector"},
    "control": {"control"},
    "content": {"content", "selector"},
    "selector": {"selector", "target", "content"},
    "credential": {"credential"},
    "command": {"command"},
}

STRONG_FIELD_MATCHES = {
    "amount": {"amount", "price"},
    "date": {"date", "due_date"},
    "time": {"time", "start_time", "end_time"},
    "subject": {"subject", "title"},
    "recipient": {"recipient", "to", "email", "user", "account", "iban"},
    "content": {"content", "body", "message", "summary", "text", "description", "note"},
    "body": {"body", "content", "message", "text"},
    "file_id": {"file_id", "id"},
    "participants": {"participants", "participant", "attendee", "attendees"},
    "channel": {"channel", "channel_id"},
}


def collect_delegated_sources(
    user_query: str,
    initial_function_trajectory: list[str],
    global_contract: IFCGlobalContract,
    tool_schemas: list[dict[str, Any]],
) -> list[DelegatedSource]:
    schemas_by_name = _schemas_by_name(tool_schemas)
    sources: list[DelegatedSource] = []
    for tool_name in initial_function_trajectory:
        tool_contract = global_contract.tools.get(tool_name)
        if tool_contract is None or tool_contract.tool_type not in {"READ_LOW", "READ_SENSITIVE"}:
            continue
        schema = schemas_by_name.get(tool_name, {})
        source_kind = _infer_source_kind(tool_name, schema)
        authorized = _user_mentions_source_kind(user_query, source_kind) or _user_mentions_read_input(user_query, schema)
        sources.append(
            DelegatedSource(
                tool_name=tool_name,
                source_path_prefix=f"{tool_name}.output",
                source_kind=source_kind,
                I_label="DELEGATED" if authorized else "TOOL_OUTPUT",
                C_label=tool_contract.output.get("C_label", "USER_PRIVATE" if tool_contract.tool_type == "READ_SENSITIVE" else "INTERNAL"),
                authorized_by_task=authorized,
                reason=(
                    "read source is explicitly indicated by the user task"
                    if authorized
                    else "read source appears in the planned trajectory but has no explicit input mention"
                ),
            )
        )
    return sources


def collect_candidate_source_fields(
    delegated_sources: list[DelegatedSource],
    initial_function_trajectory: list[str],
    global_contract: IFCGlobalContract,
    tool_schemas: list[dict[str, Any]],
) -> list[CandidateSourceField]:
    del initial_function_trajectory, global_contract
    schemas_by_name = _schemas_by_name(tool_schemas)
    candidates: list[CandidateSourceField] = []
    for source in delegated_sources:
        schema = schemas_by_name.get(source.tool_name, {})
        fields = _output_fields_from_schema(schema) or _generic_fields_for_source_kind(source.source_kind)
        for field_name, field_description in fields:
            endorsements = ["structured_extraction", "schema_validated_parse"]
            if source.authorized_by_task:
                endorsements = ["task_delegation", *endorsements, "exact_match_to_authorized_source"]
            candidates.append(
                CandidateSourceField(
                    source_path=f"{source.source_path_prefix}.{field_name}",
                    source_role=infer_field_role(field_name, field_description),
                    field_name=field_name,
                    I_after=source.I_label,
                    C_label=_field_confidentiality(field_name, source.C_label),
                    endorsements=list(dict.fromkeys(endorsements)),
                    reason=f"{field_name} is a {source.source_kind} source field from {source.tool_name}: {source.reason}",
                )
            )
    return candidates


def infer_field_role(field_name: str, field_description: str = "") -> str:
    haystack = f"{field_name} {field_description}".lower()
    for role in ROLE_PRIORITY:
        if _contains_keyword(haystack, ROLE_KEYWORDS[role]):
            return role
    return "selector"


def is_role_compatible(source_role: str, sink_role: str) -> bool:
    return source_role in COMPATIBLE_ROLES.get(sink_role, {sink_role})


def find_unique_candidate_for_sink(
    sink: str,
    global_arg: Any,
    candidates: list[CandidateSourceField],
) -> CandidateSourceField | None:
    _, argument_name = sink.split(".", 1)
    compatible = [candidate for candidate in candidates if is_role_compatible(candidate.source_role, global_arg.sink_role)]
    if not compatible:
        return None
    strong_matches = [candidate for candidate in compatible if _strong_field_match(argument_name, candidate.field_name)]
    if len(strong_matches) == 1:
        return strong_matches[0]
    if len(compatible) == 1:
        return compatible[0]
    return None


def add_binding_from_candidate(
    global_contract: IFCGlobalContract,
    flow_bindings: dict[str, list[FlowBinding]],
    sink: str,
    candidate: CandidateSourceField,
) -> None:
    tool_name, argument_name = sink.split(".", 1)
    global_arg = global_contract.tools[tool_name].args[argument_name]
    flow_bindings.setdefault(sink, []).append(
        FlowBinding(
            source_path=candidate.source_path,
            sink=sink,
            I_after=candidate.I_after,
            C_label=candidate.C_label,
            satisfies=list(global_arg.flow_constraints),
            endorsements=[endorsement for endorsement in candidate.endorsements if endorsement in global_arg.endorsements],
            declassifications=[],
            reason=candidate.reason,
        )
    )


def _candidate_satisfies_global_requirements(global_arg: Any, candidate: CandidateSourceField) -> bool:
    if "structured_source_required" in global_arg.flow_constraints and "structured_extraction" not in candidate.endorsements:
        return False
    return True


def _schemas_by_name(tool_schemas: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(schema.get("name", "")): schema for schema in tool_schemas}


def _output_fields_from_schema(schema: dict[str, Any]) -> list[tuple[str, str]]:
    for key in ("output_schema", "return_schema", "returns", "response_schema", "output"):
        fields = _fields_from_schema_fragment(schema.get(key))
        if fields:
            return fields
    return []


def _fields_from_schema_fragment(fragment: Any) -> list[tuple[str, str]]:
    if not isinstance(fragment, dict):
        return []
    properties = fragment.get("properties")
    if isinstance(properties, dict):
        return [
            (str(name), str(value.get("description", "")) if isinstance(value, dict) else "")
            for name, value in properties.items()
        ]
    return [
        (str(name), str(value.get("description", "")) if isinstance(value, dict) else "")
        for name, value in fragment.items()
        if name not in {"type", "description", "items", "required"}
    ]


def _generic_fields_for_source_kind(source_kind: str) -> list[tuple[str, str]]:
    names = GENERIC_OUTPUT_FIELD_ALIASES.get(source_kind, GENERIC_OUTPUT_FIELD_ALIASES["generic"])
    return [(name, "") for name in names]


def _infer_source_kind(tool_name: str, schema: dict[str, Any]) -> str:
    haystack = f"{tool_name} {schema.get('description', '')}".lower()
    if _contains_keyword(haystack, ["file", "document", "doc", "pdf", "txt", "workspace"]):
        return "file"
    if _contains_keyword(haystack, ["email", "inbox", "mail"]):
        return "email"
    if _contains_keyword(haystack, ["channel", "slack", "message", "chat"]):
        return "message"
    if _contains_keyword(haystack, ["calendar", "event", "meeting"]):
        return "calendar"
    if _contains_keyword(haystack, ["hotel", "restaurant", "city", "reservation", "travel"]):
        return "travel"
    return "generic"


def _user_mentions_source_kind(user_query: str, source_kind: str) -> bool:
    lower = user_query.lower()
    signals = {
        "file": [".txt", ".pdf", ".doc", ".docx", "file", "document", "report"],
        "email": ["email", "inbox", "mail", "from", "subject"],
        "message": ["channel", "slack", "message", "chat"],
        "calendar": ["calendar", "event", "meeting", "date"],
        "travel": ["hotel", "restaurant", "city", "reservation", "travel"],
        "generic": [],
    }
    return any(token in lower for token in signals.get(source_kind, []))


def _user_mentions_read_input(user_query: str, schema: dict[str, Any]) -> bool:
    lower = user_query.lower()
    for arg_name, arg_schema in schema.get("parameters", {}).get("properties", {}).items():
        arg_text = f"{arg_name} {arg_schema.get('description', '') if isinstance(arg_schema, dict) else ''}".lower()
        if _contains_keyword(arg_text, ["file", "path", "document"]) and re.search(r"\b[\w.-]+\.(?:txt|pdf|docx?|md|csv)\b", lower):
            return True
        if _contains_keyword(arg_text, ["email", "message", "channel", "calendar", "event"]):
            if _user_mentions_source_kind(user_query, _infer_source_kind(str(arg_name), {"description": arg_text})):
                return True
    return False


def _field_confidentiality(field_name: str, source_c_label: str) -> str:
    if infer_field_role(field_name) == "credential":
        return "SECRET"
    if field_name in {"amount", "price", "balance"}:
        return "SENSITIVE"
    return source_c_label


def _strong_field_match(argument_name: str, field_name: str) -> bool:
    argument = argument_name.lower()
    field = field_name.lower()
    return field == argument or field in STRONG_FIELD_MATCHES.get(argument, set())


def _contains_keyword(text: str, keywords: list[str]) -> bool:
    normalized = text.lower().replace("-", "_")
    return any(keyword in normalized for keyword in keywords)


def _explicit_endorsements(global_endorsements: list[str]) -> list[str]:
    evidence = ["user_explicit", "exact_match_to_authorized_source"]
    return [endorsement for endorsement in evidence if endorsement in global_endorsements]


def _source_delegations_from_candidates(candidates: list[CandidateSourceField]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        source = candidate.source_path.split(".output.", 1)[0]
        group = grouped.setdefault(
            source,
            {
                "source": source,
                "source_kind": "tool_output",
                "authorized_by_task": "task_delegation" in candidate.endorsements,
                "instruction_text_authorized": False,
                "default_I_label": candidate.I_after,
                "default_C_label": candidate.C_label,
                "extractable_fields": {},
            },
        )
        group["authorized_by_task"] = group["authorized_by_task"] or "task_delegation" in candidate.endorsements
        group["extractable_fields"][candidate.field_name] = {
            "source_path": candidate.source_path,
            "source_role": candidate.source_role,
            "I_after": candidate.I_after,
            "C_label": candidate.C_label,
            "endorsements": list(candidate.endorsements),
            "reason": candidate.reason,
        }
    return list(grouped.values())


def _relevant_tool_schemas(tool_schemas: list[dict[str, Any]], trajectory: list[str]) -> list[dict[str, Any]]:
    names = set(trajectory)
    return [schema for schema in tool_schemas if schema.get("name") in names]


def _task_type(initial_function_trajectory: list[str], global_contract: IFCGlobalContract) -> str:
    tool_types = [
        global_contract.tools[tool_name].tool_type
        for tool_name in initial_function_trajectory
        if tool_name in global_contract.tools
    ]
    has_action = any(tool_type == "ACTION" for tool_type in tool_types)
    has_read = any(tool_type in {"READ_LOW", "READ_SENSITIVE"} for tool_type in tool_types)
    if has_read and has_action:
        return "read_to_action_flow"
    if has_action:
        return "direct_action_flow"
    if has_read:
        return "read_only_flow"
    return "tool_trajectory_flow"
