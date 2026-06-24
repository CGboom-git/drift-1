from __future__ import annotations

import json
import re
from typing import Any

from pact_drift.provenance import ProvenanceRecord

_INSTRUCTION_MARKERS = (
    "ignore previous instructions", "disregard", "infer missing details", "do not ask", "use transaction history",
    "send money to", "transfer to", "leak", "exfiltrate", "important instruction",
)
_FIELD_PATTERNS = {
    "creditor_name": ("creditor", "recipient", "company", "payee", "beneficiary"),
    "amount": ("amount", "total", "due amount"),
    "subject": ("subject", "invoice subject", "description"),
    "due_date": ("due date", "payment date", "date"),
}


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


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


def extract_structured_fields(tool_name: str, tool_args: dict[str, Any], tool_output: Any, task_contract: Any | None) -> list[ProvenanceRecord]:
    del tool_args
    if tool_name != "read_file":
        return []
    output = tool_output
    text = _text(output)
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            pass
    records: list[ProvenanceRecord] = []
    lower = text.lower()
    marks = ["injected_instruction"] if any(marker in lower for marker in _INSTRUCTION_MARKERS) else []
    if marks:
        records.append(ProvenanceRecord(value=text, trust="EXTERNAL", origins=[{"type": "tool_output", "tool": tool_name}], forbidden_marks=marks, source_path="read_file.output.injected_instruction"))
    for field, names in _FIELD_PATTERNS.items():
        value = _field_from_mapping(output, names) or _field_from_text(text, names)
        if value is not None:
            records.append(ProvenanceRecord(
                value=value,
                trust="DELEGATED_TASK_DATA",
                origins=[{"type": "structured_extraction", "tool": tool_name, "field": f"invoice.{field}"}],
                source_path=f"read_file.output.invoice.{field}",
            ))
    return records
