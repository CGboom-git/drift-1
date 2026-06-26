from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

try:
    from json_repair import repair_json
except ImportError:  # pragma: no cover - exercised only in minimal local environments.
    def repair_json(value: str) -> str:
        return value

from pact_drift.argument_flow_validator import validate_tool_call_arguments_ifc
from pact_drift.task_flow_contract_generator import summarize_task_flow_contract
from prompts import IFC_OUT_OF_TRAJECTORY_VALIDATION_PROMPT


@dataclass
class IFCJointValidationResult:
    allowed: bool
    events: list[dict[str, Any]] = field(default_factory=list)
    updated_achieved_trajectory: list[str] = field(default_factory=list)
    rejected_sink: str | None = None
    reason: str = ""
    required_constraints: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)


def validate_tool_call_ifc_drift(
    json_tool_calls: list[dict[str, Any]],
    query: str,
    messages: list[dict[str, Any]],
    initial_function_trajectory: list[str],
    achieved_function_trajectory: list[str],
    global_contract: Any,
    task_flow_contract: Any,
    provenance_state: Any,
    client: Any | None = None,
    model: str | None = None,
    allow_action_replan: bool = False,
) -> IFCJointValidationResult:
    del model
    events: list[dict[str, Any]] = []
    updated_achieved = list(achieved_function_trajectory)
    planned_index = _next_planned_index(initial_function_trajectory, updated_achieved)
    for call in json_tool_calls:
        tool_name, _ = _arguments(call)
        tool_contract = global_contract.tools.get(tool_name)
        if tool_contract is None:
            event = _control_event(tool_name, "unknown", False, "reject", True, "tool missing from IFC global contract")
            events.append(event)
            return IFCJointValidationResult(False, events, updated_achieved, reason=event["reason"])
        in_trajectory = planned_index < len(initial_function_trajectory) and tool_name == initial_function_trajectory[planned_index]
        if not in_trajectory:
            result = _handle_out_of_trajectory(
                call,
                query,
                messages,
                initial_function_trajectory,
                updated_achieved,
                tool_contract,
                task_flow_contract,
                client,
                allow_action_replan,
            )
            events.append(result)
            if result["decision"] in {"reject", "replan_required"}:
                return IFCJointValidationResult(False, events, updated_achieved, reason=result["reason"])
            updated_achieved.append(tool_name)
            continue
        events.append(_control_event(tool_name, tool_contract.tool_type, True, "allow", False, "tool call matches planned trajectory"))
        if tool_contract.tool_type in {"READ_LOW", "READ_SENSITIVE"}:
            updated_achieved.append(tool_name)
            planned_index += 1
            continue
        allowed, argument_events = validate_tool_call_arguments_ifc([call], global_contract, task_flow_contract, provenance_state)
        for event in argument_events:
            event["part"] = "argument_flow"
        events.extend(argument_events)
        if not allowed:
            rejected = next((event for event in argument_events if not event["allowed"]), argument_events[-1] if argument_events else {})
            return IFCJointValidationResult(
                False,
                events,
                updated_achieved,
                rejected_sink=rejected.get("sink"),
                reason=rejected.get("reason", "argument flow validation failed"),
                required_constraints=rejected.get("required_constraints", []),
                allowed_paths=rejected.get("allowed_paths", []),
            )
        updated_achieved.append(tool_name)
        planned_index += 1
    return IFCJointValidationResult(True, events, updated_achieved)


def _handle_out_of_trajectory(
    call: dict[str, Any],
    query: str,
    messages: list[dict[str, Any]],
    initial_function_trajectory: list[str],
    achieved_function_trajectory: list[str],
    tool_contract: Any,
    task_flow_contract: Any,
    client: Any | None,
    allow_action_replan: bool,
) -> dict[str, Any]:
    tool_name, _ = _arguments(call)
    if tool_contract.tool_type == "READ_LOW":
        return _control_event(tool_name, tool_contract.tool_type, True, "allow_read_and_track", True, "out-of-trajectory READ_LOW is allowed and tracked")
    if tool_contract.tool_type == "READ_SENSITIVE":
        prompted = _prompt_read_sensitive_decision(
            call,
            query,
            messages,
            initial_function_trajectory,
            achieved_function_trajectory,
            tool_contract,
            task_flow_contract,
            client,
        )
        if prompted["decision"] in {"allow_read_and_track", "allow_read_and_quarantine"}:
            prompted["allowed"] = True
            prompted["part"] = "control_flow"
            prompted["out_of_trajectory"] = True
            return prompted
        return _control_event(tool_name, tool_contract.tool_type, False, "reject", True, prompted["reason"])
    if allow_action_replan:
        return _control_event(tool_name, tool_contract.tool_type, False, "replan_required", True, "out-of-trajectory ACTION requires a separate secure replan")
    return _control_event(tool_name, tool_contract.tool_type, False, "reject", True, "out-of-trajectory ACTION is rejected by default")


def _prompt_read_sensitive_decision(
    call: dict[str, Any],
    query: str,
    messages: list[dict[str, Any]],
    initial_function_trajectory: list[str],
    achieved_function_trajectory: list[str],
    tool_contract: Any,
    task_flow_contract: Any,
    client: Any | None,
) -> dict[str, Any]:
    tool_name, _ = _arguments(call)
    if client is None:
        return _control_event(tool_name, tool_contract.tool_type, True, "allow_read_and_quarantine", True, "out-of-trajectory READ_SENSITIVE is quarantined without action-flow authorization")
    user_prompt = json.dumps(
        {
            "original_user_task": query,
            "initial_function_trajectory": initial_function_trajectory,
            "current_executed_trajectory": achieved_function_trajectory,
            "proposed_tool_call": call,
            "tool_metadata": {
                "tool_type": tool_contract.tool_type,
                "check_mode": tool_contract.check_mode,
                "sink_scope": tool_contract.sink_scope,
            },
            "task_flow_contract_summary": summarize_task_flow_contract(task_flow_contract),
            "latest_message": messages[-1] if messages else None,
        },
        ensure_ascii=False,
        default=str,
        indent=2,
        sort_keys=True,
    )
    response = client.llm_run(IFC_OUT_OF_TRAJECTORY_VALIDATION_PROMPT, user_prompt, name="ifc_out_of_trajectory_read")
    try:
        data = json.loads(repair_json(response))
    except Exception:
        data = {}
    decision = data.get("decision", "allow_read_and_quarantine")
    reason = data.get("reason", "out-of-trajectory READ_SENSITIVE is quarantined without action-flow authorization")
    if decision not in {"allow_read_and_track", "allow_read_and_quarantine", "reject", "replan_required"}:
        decision = "allow_read_and_quarantine"
    return {
        "part": "control_flow",
        "tool": tool_name,
        "tool_type": tool_contract.tool_type,
        "sink_scope": tool_contract.sink_scope,
        "allowed": decision in {"allow_read_and_track", "allow_read_and_quarantine"},
        "decision": decision,
        "out_of_trajectory": True,
        "authorized_for_action_flow": False,
        "reason": reason,
    }


def _control_event(
    tool_name: str,
    tool_type: str,
    allowed: bool,
    decision: str,
    out_of_trajectory: bool,
    reason: str,
) -> dict[str, Any]:
    return {
        "part": "control_flow",
        "tool": tool_name,
        "tool_type": tool_type,
        "allowed": allowed,
        "decision": decision,
        "out_of_trajectory": out_of_trajectory,
        "authorized_for_action_flow": False,
        "reason": reason,
    }


def _next_planned_index(initial_trajectory: list[str], achieved_trajectory: list[str]) -> int:
    index = 0
    for function_name in achieved_trajectory:
        if index < len(initial_trajectory) and function_name == initial_trajectory[index]:
            index += 1
    return index


def _arguments(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = call.get("function", {})
    raw = function.get("arguments", {})
    return function.get("name", ""), json.loads(raw) if isinstance(raw, str) else raw
