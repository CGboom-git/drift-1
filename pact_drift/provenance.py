from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProvenanceRecord:
    value: Any
    trust: str
    origins: list[dict[str, Any]]
    derivation: list[dict[str, Any]] = field(default_factory=list)
    forbidden_marks: list[str] = field(default_factory=list)
    influenced_by: list[str] = field(default_factory=list)
    source_path: str | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


class ProvenanceState:
    def __init__(self) -> None:
        self.records: list[ProvenanceRecord] = []
        self.by_path: dict[str, ProvenanceRecord] = {}

    def add_record(self, record: ProvenanceRecord) -> None:
        self.records.append(record)
        if record.source_path:
            self.by_path[record.source_path] = record

    def find_by_path(self, path: str) -> ProvenanceRecord | None:
        return self.by_path.get(path)

    def find_by_value(self, value: Any) -> list[ProvenanceRecord]:
        expected = str(value).strip()
        return [record for record in self.records if str(record.value).strip() == expected]

    def to_json(self) -> list[dict[str, Any]]:
        return [record.to_json() for record in self.records]


def propagate_input_provenance(value: Any, input_record: ProvenanceRecord | None, output_path: str) -> ProvenanceRecord:
    """Create a derived output without laundering the input's trust or forbidden marks."""
    if input_record is None:
        return ProvenanceRecord(
            value=value,
            trust="EXTERNAL",
            origins=[{"type": "derived_tool_output"}],
            forbidden_marks=["untrusted_raw_text"],
            source_path=output_path,
        )
    return ProvenanceRecord(
        value=value,
        trust=input_record.trust,
        origins=list(input_record.origins),
        derivation=[{"source_path": input_record.source_path}] if input_record.source_path else [],
        forbidden_marks=list(input_record.forbidden_marks),
        source_path=output_path,
    )
