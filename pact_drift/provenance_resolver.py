from __future__ import annotations

from typing import Any

from pact_drift.provenance import ProvenanceRecord, ProvenanceState


def record_derives_from(record: ProvenanceRecord, required_path: str | None) -> bool:
    if required_path is None:
        return True
    if record.source_path == required_path:
        return True
    return any(item.get("source_path") == required_path for item in record.derivation)


def resolve_argument_provenance(tool_name: str, argument_name: str, argument_value: Any, provenance_state: ProvenanceState, task_contract: Any, global_contracts: Any, llm_client: Any | None = None) -> ProvenanceRecord:
    del global_contracts, llm_client
    constraint = task_contract.argument_source_constraints.get(f"{tool_name}.{argument_name}") if task_contract else None
    matches = provenance_state.find_by_value(argument_value)
    if constraint and constraint.must_derive_from:
        required = [record for record in matches if record_derives_from(record, constraint.must_derive_from)]
        if required:
            return required[-1]
    if matches:
        trusted = [record for record in matches if record.trust not in {"EXTERNAL", "MODEL_GUESS"}]
        return (trusted or matches)[-1]
    marks = ["model_guess"]
    if argument_name == "date" and str(argument_value).strip().lower() in {"today", "now", "current date"}:
        marks.append("current_date_default_without_user_authorization")
    return ProvenanceRecord(value=argument_value, trust="MODEL_GUESS", origins=[{"type": "model_generated"}], forbidden_marks=marks)
