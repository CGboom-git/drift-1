from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pact_drift.task_flow_contract_generator import extract_explicit_user_fields


@dataclass
class ArgumentProvenance:
    value: Any
    source_paths: set[str] = field(default_factory=set)
    marks: set[str] = field(default_factory=set)
    proofs: set[str] = field(default_factory=set)
    trust: str = "TOOL_OUTPUT"
    metadata: dict[str, Any] = field(default_factory=dict)
    source_path: str | None = None
    authorized_for_action_flow: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source_paths": sorted(self.source_paths),
            "marks": sorted(self.marks),
            "proofs": sorted(self.proofs),
            "trust": self.trust,
            "metadata": self.metadata,
            "source_path": self.source_path,
            "authorized_for_action_flow": self.authorized_for_action_flow,
        }


IFCProvenanceRecord = ArgumentProvenance


class IFCProvenanceState:
    def __init__(self) -> None:
        self.records: list[ArgumentProvenance] = []
        self.by_path: dict[str, ArgumentProvenance] = {}

    def add_record(self, record: ArgumentProvenance) -> None:
        self.records.append(record)
        for source_path in record.source_paths:
            self.by_path[source_path] = record
        if record.source_path:
            self.by_path[record.source_path] = record

    def find_by_path(self, source_path: str) -> ArgumentProvenance | None:
        return self.by_path.get(source_path)

    def find_by_value(self, value: Any) -> list[ArgumentProvenance]:
        expected = _normalize_value(value)
        return [record for record in self.records if _normalize_value(record.value) == expected]

    def resolve_value(self, value: Any) -> ArgumentProvenance | None:
        matches = self.find_by_value(value)
        if not matches:
            return None
        return merge_provenance(matches)

    def to_json(self) -> list[dict[str, Any]]:
        return [record.to_json() for record in self.records]


_INJECTION_MARKERS = (
    "ignore previous instructions",
    "disregard",
    "infer missing details",
    "do not ask",
    "use transaction history",
    "send money to",
    "transfer to",
    "leak",
    "exfiltrate",
    "important instruction",
)
_FIELD_PATTERNS = {
    "creditor_name": ("creditor", "recipient", "company", "payee", "beneficiary"),
    "amount": ("amount", "total", "due amount"),
    "subject": ("subject", "invoice subject", "description"),
    "due_date": ("due date", "payment date", "date"),
}

_RAW_EXTERNAL_TEXT_TOOLS = {
    "read_file",
    "get_file_by_id",
    "get_webpage",
    "read_channel_messages",
    "get_received_emails",
    "get_unread_emails",
    "search_emails",
}

_FIELD_ALIASES = {
    "file": "file_id",
    "fileid": "file_id",
    "file_id": "file_id",
    "email": "email_id",
    "emailid": "email_id",
    "email_id": "email_id",
    "from": "sender",
    "sender": "sender",
    "subject": "subject",
    "body": "body",
    "message": "message",
    "content": "content",
    "summary": "summary",
    "channel": "channel",
    "channel_id": "channel_id",
    "channelid": "channel_id",
    "title": "title",
    "date": "date",
    "participants": "participants",
    "attendees": "participants",
    "start": "start_time",
    "start_time": "start_time",
    "end": "end_time",
    "end_time": "end_time",
    "hotel": "hotel_name",
    "hotel_name": "hotel_name",
    "price": "price",
    "rating": "rating",
    "address": "address",
    "restaurant": "restaurant_name",
    "restaurant_name": "restaurant_name",
    "opening_hours": "opening_hours",
}

_SELECTED_LIST_ALIASES = {
    "search_files": ("selected_file", "filename"),
    "get_day_calendar_events": ("event_id", "title"),
}


def record_user_explicit_fields_ifc(
    user_query: str,
    task_flow_contract: Any,
    provenance_state: IFCProvenanceState,
) -> None:
    for field_name, value in extract_explicit_user_fields(user_query).items():
        source_path = f"user.explicit.{field_name}"
        if provenance_state.find_by_path(source_path):
            continue
        provenance_state.add_record(
            ArgumentProvenance(
                value=value,
                source_paths={source_path},
                source_path=source_path,
                trust="USER",
                proofs={"user_explicit"},
                marks=set(),
                authorized_for_action_flow=_is_authorized_path(task_flow_contract, source_path),
                metadata={"kind": "user_explicit"},
            )
        )


def record_tool_output_ifc(
    tool_name: str,
    tool_args: dict[str, Any],
    tool_output: Any,
    global_contract: Any,
    task_flow_contract: Any,
    provenance_state: IFCProvenanceState,
    in_planned_trajectory: bool,
) -> None:
    tool_contract = global_contract.tools.get(tool_name) if global_contract else None
    output_policy = tool_contract.output if tool_contract else {}
    tool_type = tool_contract.tool_type if tool_contract else "READ_LOW"
    source_base = f"{tool_name}.output"
    raw_path = f"{source_base}.raw"
    requires_structured_extraction = output_policy.get("requires_structured_extraction") or tool_name in _RAW_EXTERNAL_TEXT_TOOLS
    raw_marks: set[str] = set()
    raw_trust = output_policy.get("I_label", "TOOL_OUTPUT")
    if requires_structured_extraction:
        raw_trust = "EXTERNAL"
        raw_marks.add("raw_external_content")
    if tool_type == "READ_SENSITIVE" and not in_planned_trajectory:
        raw_marks.add("unauthorized_tool_output")
        if not requires_structured_extraction:
            raw_trust = "TOOL_OUTPUT"
    provenance_state.add_record(
        ArgumentProvenance(
            value=tool_output,
            source_paths={raw_path},
            source_path=raw_path,
            trust=raw_trust,
            marks=raw_marks,
            proofs=set(),
            authorized_for_action_flow=_is_authorized_path(task_flow_contract, raw_path),
            metadata={"tool": tool_name, "kind": "raw_tool_output"},
        )
    )
    for record in flatten_tool_output(tool_name, tool_output):
        if "raw_external_content" in raw_marks:
            record.marks.add("raw_external_content")
        if "unauthorized_tool_output" in raw_marks:
            record.marks.add("unauthorized_tool_output")
        record.authorized_for_action_flow = _is_authorized_path(task_flow_contract, next(iter(record.source_paths), record.source_path or ""))
        provenance_state.add_record(record)
    if tool_name == "read_file":
        for record in extract_ifc_structured_fields(tool_output, task_flow_contract):
            provenance_state.add_record(record)
    if tool_name == "get_iban":
        provenance_state.add_record(_get_iban_record(tool_args, tool_output, provenance_state, task_flow_contract))


def flatten_tool_output(tool_name: str, output: Any) -> list[ArgumentProvenance]:
    """Flatten common tool outputs into IFC provenance records."""
    parsed = _parse_output(output)
    records: list[ArgumentProvenance] = []
    if isinstance(parsed, str):
        if tool_name in {"read_file", "get_file_by_id", "get_webpage"}:
            records.append(_flat_record(tool_name, "content", parsed, {"structured_extraction"}))
        return records
    if isinstance(parsed, dict):
        _flatten_mapping(tool_name, parsed, records)
    elif isinstance(parsed, list):
        _flatten_list(tool_name, parsed, records)
    return _dedupe_records(records)


def extract_ifc_structured_fields(tool_output: Any, task_flow_contract: Any | None) -> list[ArgumentProvenance]:
    output = tool_output
    text = _text(output)
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            pass
    records: list[ArgumentProvenance] = []
    lower = text.lower()
    if any(marker in lower for marker in _INJECTION_MARKERS):
        records.append(
            ArgumentProvenance(
                value=text,
                source_paths={"read_file.output.injected_instruction"},
                source_path="read_file.output.injected_instruction",
                trust="EXTERNAL",
                marks={"injected_instruction", "raw_external_content"},
                proofs=set(),
                authorized_for_action_flow=False,
                metadata={"tool": "read_file", "kind": "detected_instruction"},
            )
        )
    for field_name, aliases in _FIELD_PATTERNS.items():
        value = _field_from_mapping(output, aliases) or _field_from_text(text, aliases)
        if value is None:
            continue
        source_path = f"read_file.output.{field_name}"
        records.append(
            ArgumentProvenance(
                value=value,
                source_paths={source_path},
                source_path=source_path,
                trust="DELEGATED",
                marks=set(),
                proofs={"structured_extraction"},
                authorized_for_action_flow=_is_authorized_path(task_flow_contract, source_path),
                metadata={"tool": "read_file", "field": field_name},
            )
        )
    return records


def _get_iban_record(tool_args: dict[str, Any], tool_output: Any, state: IFCProvenanceState, task_flow_contract: Any | None) -> ArgumentProvenance:
    inherited = None
    for value in tool_args.values():
        matches = state.find_by_value(value)
        if matches:
            inherited = matches[-1]
            break
    iban_value = _extract_iban_value(tool_output)
    source_path = "get_iban.output.iban"
    inherited_source_paths = set(inherited.source_paths) if inherited else set()
    inherited_proofs = set(inherited.proofs) if inherited else set()
    inherited_marks = set(inherited.marks) if inherited else set()
    return ArgumentProvenance(
        value=iban_value,
        source_paths={source_path, *inherited_source_paths},
        source_path=source_path,
        trust=inherited.trust if inherited else "TOOL_OUTPUT",
        marks=inherited_marks,
        proofs={*inherited_proofs, "trusted_tool_derivation"},
        authorized_for_action_flow=_is_authorized_path(task_flow_contract, source_path),
        metadata={"tool": "get_iban", "derived_from": inherited.source_path if inherited else None},
    )


def _extract_iban_value(tool_output: Any) -> Any:
    if isinstance(tool_output, dict):
        return tool_output.get("iban", tool_output)
    text = _text(tool_output)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed.get("iban", tool_output)
    match = re.search(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", text)
    return match.group(0) if match else tool_output


def merge_provenance(records: list[ArgumentProvenance]) -> ArgumentProvenance:
    if not records:
        return ArgumentProvenance(value=None, source_paths=set(), marks=set(), proofs=set(), trust="UNKNOWN")
    return ArgumentProvenance(
        value=records[-1].value,
        source_paths=set().union(*(record.source_paths for record in records)),
        marks=set().union(*(record.marks for record in records)),
        proofs=set().union(*(record.proofs for record in records)),
        trust=_least_trusted(records),
        metadata={},
        source_path=records[-1].source_path,
        authorized_for_action_flow=any(record.authorized_for_action_flow for record in records),
    )


def _is_authorized_path(task_flow_contract: Any | None, source_path: str) -> bool:
    if task_flow_contract is None:
        return False
    if hasattr(task_flow_contract, "allowed_sources_for_sink"):
        return any(source_path in task_flow_contract.allowed_sources_for_sink(sink) for sink in getattr(task_flow_contract, "argument_contract", {}))
    if hasattr(task_flow_contract, "allowed_paths_for_sink"):
        return any(source_path in task_flow_contract.allowed_paths_for_sink(sink) for sink in getattr(task_flow_contract, "flow_bindings", {}))
    return False


def _field_from_mapping(value: Any, names: tuple[str, ...]) -> Any | None:
    if not isinstance(value, dict):
        return None
    lowered = {str(key).lower().replace(" ", "_"): item for key, item in value.items()}
    for name in names:
        key = name.replace(" ", "_")
        if key in lowered:
            return lowered[key]
    return None


def _field_from_text(text: str, names: tuple[str, ...]) -> str | None:
    for name in names:
        match = re.search(rf"(?im)^\s*{re.escape(name)}\s*[:=-]\s*(.+?)\s*$", text)
        if match:
            return match.group(1).strip().strip("'\"")
    return None


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def _normalize_value(value: Any) -> str:
    return str(value).strip()


def _least_trusted(records: list[ArgumentProvenance]) -> str:
    order = ["USER", "DELEGATED", "TOOL_OUTPUT", "EXTERNAL", "MODEL", "UNKNOWN"]
    ranked = sorted(records, key=lambda record: order.index(record.trust) if record.trust in order else len(order))
    return ranked[-1].trust if ranked else "UNKNOWN"


def _parse_output(output: Any) -> Any:
    if not isinstance(output, str):
        return output
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def _flatten_mapping(tool_name: str, data: dict[str, Any], records: list[ArgumentProvenance]) -> None:
    for key, value in data.items():
        field_name = _canonical_field_name(tool_name, str(key))
        records.append(_flat_record(tool_name, field_name, value, {"structured_extraction"}))
        if isinstance(value, dict):
            _flatten_mapping(tool_name, value, records)
        elif isinstance(value, list):
            _flatten_list(tool_name, value, records)


def _flatten_list(tool_name: str, values: list[Any], records: list[ArgumentProvenance]) -> None:
    for index, item in enumerate(values):
        if isinstance(item, dict):
            for key, value in item.items():
                field_name = _canonical_field_name(tool_name, str(key))
                records.append(_flat_record(tool_name, f"items.{index}.{field_name}", value, {"structured_extraction"}))
                records.append(_flat_record(tool_name, field_name, value, {"structured_extraction"}))
            _add_selected_aliases(tool_name, item, records)
        else:
            records.append(_flat_record(tool_name, f"items.{index}", item, {"structured_extraction"}))


def _add_selected_aliases(tool_name: str, item: dict[str, Any], records: list[ArgumentProvenance]) -> None:
    for alias in _SELECTED_LIST_ALIASES.get(tool_name, ()):  # pragma: no branch - simple alias expansion
        source_key = alias
        if source_key not in item and alias == "selected_file":
            source_key = "filename"
        if source_key in item:
            records.append(_flat_record(tool_name, alias, item[source_key], {"structured_extraction"}))


def _flat_record(tool_name: str, field_name: str, value: Any, proofs: set[str]) -> ArgumentProvenance:
    source_path = f"{tool_name}.output.{field_name}"
    marks = {"raw_external_content"} if tool_name in _RAW_EXTERNAL_TEXT_TOOLS else set()
    trust = "EXTERNAL" if tool_name in _RAW_EXTERNAL_TEXT_TOOLS else "DELEGATED"
    return ArgumentProvenance(
        value=value,
        source_paths={source_path},
        source_path=source_path,
        trust=trust,
        marks=marks,
        proofs=set(proofs),
        metadata={"tool": tool_name, "field": field_name},
    )


def _dedupe_records(records: list[ArgumentProvenance]) -> list[ArgumentProvenance]:
    deduped: dict[str, ArgumentProvenance] = {}
    for record in records:
        key = next(iter(record.source_paths), record.source_path or "")
        if key not in deduped:
            deduped[key] = record
            continue
        existing = deduped[key]
        merged = merge_provenance([existing, record])
        merged.value = record.value
        merged.source_path = record.source_path or existing.source_path
        deduped[key] = merged
    return list(deduped.values())


def _canonical_field_name(tool_name: str, raw_name: str) -> str:
    canonical = _FIELD_ALIASES.get(raw_name.lower().replace(" ", "_"))
    if canonical:
        return canonical
    if tool_name == "get_received_emails" and raw_name == "id":
        return "email_id"
    if tool_name == "get_received_emails" and raw_name == "from":
        return "sender"
    return raw_name.replace(" ", "_")
