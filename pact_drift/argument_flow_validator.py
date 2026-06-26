from __future__ import annotations

import json
from typing import Any

from pact_drift.ifc_contract_schema import confidentiality_at_most, ifc_to_jsonable, integrity_at_least
from pact_drift.ifc_provenance import IFCProvenanceRecord


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
    candidate = _resolve_provenance(value, provenance_state, allowed_paths, sink)
    matched_binding = _binding_for_source(task_flow_contract, sink, candidate.source_path)
    reasons: list[str] = []
    violation_types: list[str] = []
    if matched_binding is None:
        reasons.append("source_path_not_authorized_by_task")
    if not integrity_at_least(candidate.I_label, global_argument.I_min):
        reasons.append("integrity_label_below_required_minimum")
        violation_types.append("integrity")
    if not confidentiality_at_most(candidate.C_label, global_argument.C_max):
        if not (matched_binding and matched_binding.declassifications):
            reasons.append("confidentiality_label_exceeds_allowed_maximum")
            violation_types.append("confidentiality")
    forbidden = set(candidate.marks) & set(global_argument.deny_marks)
    if forbidden:
        reasons.append(f"forbidden_marks:{','.join(sorted(forbidden))}")
    if matched_binding is not None:
        missing_constraints = set(global_argument.flow_constraints) - set(matched_binding.satisfies)
        if missing_constraints:
            reasons.append(f"missing_required_flow_constraints:{','.join(sorted(missing_constraints))}")
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
    }


def _arguments(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = call.get("function", {})
    raw = function.get("arguments", {})
    return function.get("name", ""), json.loads(raw) if isinstance(raw, str) else raw


def _resolve_provenance(value: Any, provenance_state: Any, allowed_paths: list[str], sink: str) -> IFCProvenanceRecord:
    matches = provenance_state.find_by_value(value) if provenance_state else []
    authorized = [record for record in matches if record.source_path in allowed_paths]
    if authorized:
        return authorized[-1]
    if matches:
        return matches[-1]
    return IFCProvenanceRecord(
        value=value,
        source_path=f"model.generated.{sink}",
        I_label="EXTERNAL",
        C_label="INTERNAL",
        marks=["model_inferred_unverified", "unknown_origin"],
        transformations=[],
        authorized_for_action_flow=False,
        metadata={"kind": "model_generated"},
    )


def _binding_for_source(task_flow_contract: Any, sink: str, source_path: str) -> Any | None:
    if task_flow_contract is None:
        return None
    for binding in task_flow_contract.bindings_for_sink(sink):
        if binding.source_path == source_path:
            return binding
    return None
