from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from pact_drift.ifc_contract_schema import confidentiality_at_most, ifc_to_jsonable, integrity_at_least
from pact_drift.ifc_provenance import IFCProvenanceRecord


@dataclass
class ProvenanceResolution:
    record: IFCProvenanceRecord | None
    ambiguous: bool = False
    ambiguity_reason: str = ""
    candidates: list[IFCProvenanceRecord] = field(default_factory=list)


def validate_tool_call_arguments_ifc(
    json_tool_calls: list[dict[str, Any]],
    global_contract: Any,
    task_flow_contract: Any,
    provenance_state: Any,
) -> tuple[bool, list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    allowed = True
    for call in json_tool_calls:
        tool_name, arguments = _arguments(call)
        tool_contract = global_contract.tools.get(tool_name)
        if tool_contract is None or tool_contract.tool_type != "ACTION":
            continue
        for argument_name, argument_value in arguments.items():
            global_argument = tool_contract.args.get(argument_name)
            if global_argument is None:
                continue
            sink = f"{tool_name}.{argument_name}"
            event = validate_single_argument_flow(
                sink=sink,
                value=argument_value,
                global_argument=global_argument,
                task_flow_contract=task_flow_contract,
                provenance_state=provenance_state,
            )
            events.append(event)
            if not event["allowed"]:
                allowed = False
    return allowed, events


def validate_single_argument_flow(
    sink: str,
    value: Any,
    global_argument: Any,
    task_flow_contract: Any,
    provenance_state: Any,
) -> dict[str, Any]:
    allowed_paths = task_flow_contract.allowed_paths_for_sink(sink) if task_flow_contract else []
    resolution = _resolve_provenance(value, provenance_state, allowed_paths, sink)
    candidate = resolution.record
    if candidate is None:
        candidate = IFCProvenanceRecord(
            value=value,
            source_path=f"model.generated.{sink}",
            I_label="EXTERNAL",
            C_label="INTERNAL",
            marks=["model_inferred_unverified", "unknown_origin"],
            transformations=[],
            authorized_for_action_flow=False,
            metadata={"kind": "model_generated"},
        )
    matched_binding = _binding_for_source(task_flow_contract, sink, candidate.source_path)
    reasons: list[str] = []
    violation_types: list[str] = []
    if resolution.ambiguous:
        reasons.append("ambiguous_provenance")
    if matched_binding is None:
        reasons.append("source_path_not_authorized_by_task")
    if not integrity_at_least(candidate.I_label, global_argument.I_min):
        reasons.append("integrity_label_below_required_minimum")
        violation_types.append("integrity")
    if not confidentiality_at_most(candidate.C_label, global_argument.C_max):
        required_declassifications = set(matched_binding.declassifications) if matched_binding else set()
        actual_declassifications = set(candidate.metadata.get("declassifications", []))
        allowed_declassifications = set(global_argument.declassifications)
        if not required_declassifications:
            reasons.append("confidentiality_label_exceeds_allowed_maximum")
        elif not required_declassifications.issubset(allowed_declassifications):
            reasons.append("declassification_not_allowed_by_global_contract")
        elif not required_declassifications.issubset(actual_declassifications):
            reasons.append("declassification_evidence_missing")
        violation_types.append("confidentiality")
    forbidden = set(candidate.marks) & set(global_argument.deny_marks)
    if forbidden:
        reasons.append(f"forbidden_marks:{','.join(sorted(forbidden))}")
    if matched_binding is not None:
        missing_constraints = set(global_argument.flow_constraints) - set(matched_binding.satisfies)
        if missing_constraints:
            reasons.append(f"missing_required_flow_constraints:{','.join(sorted(missing_constraints))}")
        required_endorsements = set(matched_binding.endorsements)
        actual_transformations = set(candidate.transformations)
        if not required_endorsements.issubset(actual_transformations):
            reasons.append("endorsement_evidence_missing")
    required_constraints = list(global_argument.flow_constraints)
    allowed = not reasons
    return {
        "sink": sink,
        "value": value,
        "allowed": allowed,
        "reason": "authorized_flow" if allowed else "; ".join(reasons),
        "violation_types": violation_types,
        "global_contract": ifc_to_jsonable(global_argument),
        "matched_task_binding": matched_binding.to_json() if matched_binding else None,
        "resolved_provenance": candidate.to_json(),
        "required_constraints": required_constraints,
        "allowed_paths": allowed_paths,
        "required_endorsements": sorted(matched_binding.endorsements) if matched_binding else [],
        "actual_transformations": sorted(candidate.transformations),
        "required_declassifications": sorted(matched_binding.declassifications) if matched_binding else [],
        "actual_declassifications": sorted(candidate.metadata.get("declassifications", [])),
        "ambiguous_provenance": resolution.ambiguous,
        "ambiguity_reason": resolution.ambiguity_reason,
        "candidate_source_paths": [record.source_path for record in resolution.candidates],
    }


def _arguments(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = call.get("function", {})
    raw = function.get("arguments", {})
    return function.get("name", ""), json.loads(raw) if isinstance(raw, str) else raw


def _resolve_provenance(value: Any, provenance_state: Any, allowed_paths: list[str], sink: str) -> ProvenanceResolution:
    matches = provenance_state.find_by_value(value) if provenance_state else []
    if not matches:
        return ProvenanceResolution(
            record=IFCProvenanceRecord(
                value=value,
                source_path=f"model.generated.{sink}",
                I_label="EXTERNAL",
                C_label="INTERNAL",
                marks=["model_inferred_unverified", "unknown_origin"],
                transformations=[],
                authorized_for_action_flow=False,
                metadata={"kind": "model_generated"},
            )
        )
    if len(matches) == 1:
        return ProvenanceResolution(record=matches[0], candidates=matches)

    authorized = [record for record in matches if record.source_path in allowed_paths]
    marked_candidates = [record for record in matches if record.marks]
    if len(authorized) == 1 and not marked_candidates:
        selected = _with_resolution_note(authorized[0], "ambiguity_resolved_by_allowed_path")
        return ProvenanceResolution(record=selected, candidates=matches)
    if authorized and marked_candidates:
        return ProvenanceResolution(
            record=authorized[-1],
            ambiguous=True,
            ambiguity_reason="same value also appears in a marked provenance candidate",
            candidates=matches,
        )
    if len(authorized) > 1:
        first_signature = _provenance_signature(authorized[0])
        if all(_provenance_signature(record) == first_signature for record in authorized[1:]):
            selected = _with_resolution_note(authorized[-1], "ambiguity_resolved_by_equivalent_allowed_candidates")
            return ProvenanceResolution(record=selected, candidates=matches)
        return ProvenanceResolution(
            record=authorized[-1],
            ambiguous=True,
            ambiguity_reason="multiple allowed provenance candidates have incompatible labels or marks",
            candidates=matches,
        )
    return ProvenanceResolution(
        record=_most_polluted_or_last(matches),
        candidates=matches,
    )


def _binding_for_source(task_flow_contract: Any, sink: str, source_path: str) -> Any | None:
    if task_flow_contract is None:
        return None
    for binding in task_flow_contract.bindings_for_sink(sink):
        if binding.source_path == source_path:
            return binding
    return None


def _provenance_signature(record: IFCProvenanceRecord) -> tuple[Any, ...]:
    return (
        record.I_label,
        record.C_label,
        tuple(sorted(record.marks)),
        tuple(sorted(record.transformations)),
        record.authorized_for_action_flow,
    )


def _with_resolution_note(record: IFCProvenanceRecord, note: str) -> IFCProvenanceRecord:
    data = record.to_json()
    metadata = dict(data.get("metadata", {}))
    metadata["provenance_resolution"] = note
    data["metadata"] = metadata
    return IFCProvenanceRecord(**data)


def _most_polluted_or_last(records: list[IFCProvenanceRecord]) -> IFCProvenanceRecord:
    marked = [record for record in records if record.marks]
    if marked:
        return marked[-1]
    return records[-1]
