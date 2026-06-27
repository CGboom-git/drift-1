from __future__ import annotations

import json
from typing import Any

from pact_drift.ifc_provenance import ArgumentProvenance, IFCProvenanceRecord


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
    allowed_sources = task_flow_contract.allowed_sources_for_sink(sink) if task_flow_contract else []
    required_proofs = list(getattr(task_flow_contract.argument_contract.get(sink), "required_proofs", [])) if task_flow_contract else []
    actual = _resolve_provenance(value, provenance_state, sink)
    if actual is None:
        actual = ArgumentProvenance(
            value=value,
            source_paths={f"model.generated.{sink}"},
            source_path=f"model.generated.{sink}",
            trust="MODEL",
            marks={"model_guess", "unknown_origin"},
            proofs=set(),
            metadata={"kind": "model_generated"},
        )
    actual_sources = set(actual.source_paths)
    actual_proofs = set(actual.proofs)
    actual_marks = set(actual.marks)
    reasons: list[str] = []
    if not actual_sources.issubset(set(allowed_sources)):
        reasons.append("source_not_authorized")
    if not set(required_proofs).issubset(actual_proofs):
        reasons.append("required_proof_missing")
    forbidden = actual_marks & set(global_argument.deny_marks)
    if forbidden:
        reasons.append(f"deny_mark_hit:{','.join(sorted(forbidden))}")
    allowed = not reasons
    return {
        "sink": sink,
        "value": value,
        "allowed": allowed,
        "reason": "authorized_flow" if allowed else "; ".join(reasons),
        "global_contract": _global_argument_to_json(global_argument),
        "allowed_sources": allowed_sources,
        "actual_sources": sorted(actual_sources),
        "required_proofs": required_proofs,
        "actual_proofs": sorted(actual_proofs),
        "actual_marks": sorted(actual_marks),
        "resolved_provenance": actual.to_json(),
    }


def _resolve_provenance(value: Any, provenance_state: Any, sink: str) -> ArgumentProvenance | None:
    if provenance_state is None:
        return None
    matches = provenance_state.find_by_value(value)
    if not matches:
        return None
    return _merge_matches(matches, sink)


def _merge_matches(matches: list[IFCProvenanceRecord], sink: str) -> ArgumentProvenance:
    source_paths = set().union(*(record.source_paths for record in matches))
    marks = set().union(*(record.marks for record in matches))
    proofs = set().union(*(record.proofs for record in matches))
    return ArgumentProvenance(
        value=matches[-1].value,
        source_paths=source_paths or {f"model.generated.{sink}"},
        source_path=matches[-1].source_path,
        trust=_least_trusted(matches),
        marks=marks,
        proofs=proofs,
        metadata={"candidate_count": len(matches)},
        authorized_for_action_flow=any(record.authorized_for_action_flow for record in matches),
    )


def _arguments(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = call.get("function", {})
    raw = function.get("arguments", {})
    return function.get("name", ""), json.loads(raw) if isinstance(raw, str) else raw


def _least_trusted(records: list[IFCProvenanceRecord]) -> str:
    order = ["USER", "DELEGATED", "TOOL_OUTPUT", "EXTERNAL", "MODEL", "UNKNOWN"]
    ranked = sorted(records, key=lambda record: order.index(record.trust) if record.trust in order else len(order))
    return ranked[-1].trust if ranked else "UNKNOWN"


def _global_argument_to_json(global_argument: Any) -> dict[str, Any]:
    return {
        "name": getattr(global_argument, "name", ""),
        "sink_role": getattr(global_argument, "sink_role", ""),
        "I_min": getattr(global_argument, "I_min", ""),
        "C_max": getattr(global_argument, "C_max", ""),
        "deny_marks": list(getattr(global_argument, "deny_marks", [])),
        "flow_constraints": list(getattr(global_argument, "flow_constraints", [])),
        "endorsements": list(getattr(global_argument, "endorsements", [])),
        "declassifications": list(getattr(global_argument, "declassifications", [])),
    }
