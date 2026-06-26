from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from pact_drift.task_flow_contract_generator import extract_explicit_user_fields


@dataclass
class IFCProvenanceRecord:
    value: Any
    source_path: str
    I_label: str
    C_label: str
    marks: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)
    authorized_for_action_flow: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


class IFCProvenanceState:
    def __init__(self) -> None:
        self.records: list[IFCProvenanceRecord] = []
        self.by_path: dict[str, IFCProvenanceRecord] = {}

    def add_record(self, record: IFCProvenanceRecord) -> None:
        self.records.append(record)
        self.by_path[record.source_path] = record

    def find_by_path(self, source_path: str) -> IFCProvenanceRecord | None:
        return self.by_path.get(source_path)

    def find_by_value(self, value: Any) -> list[IFCProvenanceRecord]:
        expected = _normalize_value(value)
        return [record for record in self.records if _normalize_value(record.value) == expected]

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
            IFCProvenanceRecord(
                value=value,
                source_path=source_path,
                I_label="USER",
                C_label="USER_PRIVATE",
                marks=[],
                transformations=["user_explicit", "exact_match_to_authorized_source"],
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
    raw_i = output_policy.get("I_label", "TOOL_OUTPUT")
    raw_c = output_policy.get("C_label", "INTERNAL")
    raw_marks: list[str] = []
    requires_structured_extraction = output_policy.get("requires_structured_extraction") or tool_name in _RAW_EXTERNAL_TEXT_TOOLS
    if requires_structured_extraction:
        raw_i = "EXTERNAL"
        raw_marks.append("raw_external_content")
    if tool_type == "READ_SENSITIVE" and not in_planned_trajectory:
        if not requires_structured_extraction:
            raw_i = "TOOL_OUTPUT"
        raw_marks.append("unauthorized_tool_output")
    raw_path = f"{source_base}.raw"
    provenance_state.add_record(
        IFCProvenanceRecord(
            value=tool_output,
            source_path=raw_path,
            I_label=raw_i,
            C_label=raw_c,
            marks=_unique(raw_marks),
            transformations=[],
            authorized_for_action_flow=_is_authorized_path(task_flow_contract, raw_path),
            metadata={"tool": tool_name, "kind": "raw_tool_output"},
        )
    )
    if tool_name == "read_file":
        for record in extract_ifc_structured_fields(tool_output, task_flow_contract):
            provenance_state.add_record(record)
    if tool_name == "get_iban":
        provenance_state.add_record(_get_iban_record(tool_args, tool_output, provenance_state, task_flow_contract))


def extract_ifc_structured_fields(tool_output: Any, task_flow_contract: Any | None) -> list[IFCProvenanceRecord]:
    output = tool_output
    text = _text(output)
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            pass
    records: list[IFCProvenanceRecord] = []
    lower = text.lower()
    if any(marker in lower for marker in _INJECTION_MARKERS):
        records.append(
            IFCProvenanceRecord(
                value=text,
                source_path="read_file.output.injected_instruction",
                I_label="EXTERNAL",
                C_label="USER_PRIVATE",
                marks=["injected_instruction", "raw_external_content"],
                transformations=[],
                authorized_for_action_flow=False,
                metadata={"tool": "read_file", "kind": "detected_instruction"},
            )
        )
    for field_name, aliases in _FIELD_PATTERNS.items():
        value = _field_from_mapping(output, aliases) or _field_from_text(text, aliases)
        if value is None:
            continue
        source_path = f"read_file.output.invoice.{field_name}"
        records.append(
            IFCProvenanceRecord(
                value=value,
                source_path=source_path,
                I_label="DELEGATED",
                C_label="SENSITIVE" if field_name in {"amount", "due_date"} else "USER_PRIVATE",
                marks=[],
                transformations=["task_delegation", "structured_extraction", "schema_validated_parse", "exact_match_to_authorized_source"],
                authorized_for_action_flow=_is_authorized_path(task_flow_contract, source_path),
                metadata={"tool": "read_file", "field": f"invoice.{field_name}"},
            )
        )
    return records


def _get_iban_record(tool_args: dict[str, Any], tool_output: Any, state: IFCProvenanceState, task_flow_contract: Any | None) -> IFCProvenanceRecord:
    inherited = None
    for value in tool_args.values():
        matches = state.find_by_value(value)
        if matches:
            inherited = matches[-1]
            break
    iban_value = _extract_iban_value(tool_output)
    source_path = "get_iban.output.iban"
    return IFCProvenanceRecord(
        value=iban_value,
        source_path=source_path,
        I_label=inherited.I_label if inherited else "TOOL_OUTPUT",
        C_label=inherited.C_label if inherited else "SENSITIVE",
        marks=list(inherited.marks) if inherited else [],
        transformations=[*(inherited.transformations if inherited else []), "trusted_tool_derivation"],
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


def _is_authorized_path(task_flow_contract: Any | None, source_path: str) -> bool:
    if task_flow_contract is None:
        return False
    return any(source_path in task_flow_contract.allowed_paths_for_sink(sink) for sink in task_flow_contract.flow_bindings)


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


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
