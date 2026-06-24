from __future__ import annotations

import json
from typing import Any

from pact_drift.contracts import contracts_to_jsonable
from pact_drift.provenance_resolver import record_derives_from, resolve_argument_provenance


def _arguments(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = call.get("function", {})
    raw = function.get("arguments", {})
    return function.get("name", ""), json.loads(raw) if isinstance(raw, str) else raw


def validate_tool_call_arguments(json_tool_calls: list[dict[str, Any]], global_contracts: Any, task_contract: Any, provenance_state: Any, args: Any) -> tuple[bool, list[dict[str, Any]]]:
    del args
    events: list[dict[str, Any]] = []
    allowed = True
    for call in json_tool_calls:
        tool_name, arguments = _arguments(call)
        tool_contract = global_contracts.tools.get(tool_name)
        if tool_contract is None or tool_contract.tool_type in {"READ_LOW", "READ_SENSITIVE"}:
            continue
        for argument_name, argument_value in arguments.items():
            argument_contract = tool_contract.arguments.get(argument_name)
            if argument_contract is None:
                continue
            provenance = resolve_argument_provenance(tool_name, argument_name, argument_value, provenance_state, task_contract, global_contracts)
            task_constraint = task_contract.argument_source_constraints.get(f"{tool_name}.{argument_name}") if task_contract else None
            reasons: list[str] = []
            if not argument_contract.allow_model_generated and provenance.trust == "MODEL_GUESS":
                reasons.append("argument provenance is MODEL_GUESS")
            forbidden = set(argument_contract.forbidden_origins)
            if task_constraint:
                forbidden.update(task_constraint.forbidden_sources)
                if task_constraint.must_derive_from and not record_derives_from(provenance, task_constraint.must_derive_from):
                    reasons.append(f"argument does not derive from {task_constraint.must_derive_from}")
                if task_constraint.upstream_must_derive_from and not record_derives_from(provenance, task_constraint.upstream_must_derive_from):
                    reasons.append(f"argument does not derive upstream from {task_constraint.upstream_must_derive_from}")
            marks = set(provenance.forbidden_marks)
            overlap = marks & forbidden
            if overlap:
                reasons.append(f"forbidden provenance marks: {', '.join(sorted(overlap))}")
            decision = "allow" if not reasons else "reject"
            events.append({"tool": tool_name, "argument": argument_name, "value": argument_value, "decision": decision, "reason": "; ".join(reasons) or "authorized provenance", "resolved_provenance": provenance.to_json(), "global_contract": contracts_to_jsonable(argument_contract), "task_constraint": contracts_to_jsonable(task_constraint) if task_constraint else None})
            if reasons:
                allowed = False
    return allowed, events
