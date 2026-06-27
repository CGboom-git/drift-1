from __future__ import annotations

import json

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.ifc_provenance import IFCProvenanceRecord, IFCProvenanceState
from pact_drift.joint_validator import validate_tool_call_ifc_drift
from pact_drift.task_flow_contract import ArgumentAuthorityBinding, TaskFlowContract, UnresolvedArgumentBinding


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _global():
    return generate_ifc_global_contract(
        [
            _schema("send_money", {"amount": {"type": "number"}}, "Send money."),
            _schema("search_web", {"query": _arg("search query")}, "Search public web."),
            _schema("read_file", {"file_path": _arg()}, "Read a file."),
        ],
        "agentdojo",
        {"name": "agentdojo", "version": "v1"},
    )


def _call(tool_name: str, **arguments):
    return [{"function": {"name": tool_name, "arguments": json.dumps(arguments)}}]


def _task(global_contract):
    return TaskFlowContract(
        contract_version="argument_authority_contract_v1",
        allowed_trajectory=["send_money"],
        argument_contract={
            "send_money.amount": ArgumentAuthorityBinding(
                allowed_sources=["read_file.output.invoice.amount"],
                required_proofs=["structured_extraction"],
                reason="test",
            )
        },
        unresolved_bindings=[UnresolvedArgumentBinding(sink="send_money.recipient", reason="missing", policy="safe_refusal")],
    )


def _state():
    state = IFCProvenanceState()
    state.add_record(IFCProvenanceRecord("50.0", {"read_file.output.invoice.amount"}, set(), {"structured_extraction"}, trust="DELEGATED", source_path="read_file.output.invoice.amount"))
    return state


def test_in_trajectory_action_enters_argument_flow_validation() -> None:
    global_contract = _global()
    result = validate_tool_call_ifc_drift(
        _call("send_money", amount="50.0"),
        query="pay invoice",
        messages=[],
        initial_function_trajectory=["send_money"],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=_state(),
    )
    assert result.allowed
    assert any(event.get("part") == "argument_flow" for event in result.events)


def test_out_of_trajectory_read_low_is_allowed_and_tracked() -> None:
    global_contract = _global()
    result = validate_tool_call_ifc_drift(
        _call("search_web", query="weather"),
        query="pay invoice",
        messages=[],
        initial_function_trajectory=["send_money"],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=_state(),
    )
    assert result.allowed
    assert result.events[0]["decision"] == "allow_read_and_track"


def test_drift_style_allows_read_low_before_next_planned_action() -> None:
    global_contract = _global()
    result = validate_tool_call_ifc_drift(
        _call("search_web", query="weather"),
        query="pay invoice",
        messages=[],
        initial_function_trajectory=["send_money"],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=_state(),
        control_mode="drift_style",
    )
    assert result.allowed
    assert result.events[0]["decision"] == "allow"
    assert result.events[0]["out_of_trajectory"] is False


def test_out_of_trajectory_read_sensitive_is_quarantined_without_client() -> None:
    global_contract = _global()
    result = validate_tool_call_ifc_drift(
        _call("read_file", file_path="notes.txt"),
        query="pay invoice",
        messages=[],
        initial_function_trajectory=["send_money"],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=_state(),
    )
    assert result.allowed
    assert result.events[0]["decision"] == "allow_read_and_quarantine"
    assert result.events[0]["authorized_for_action_flow"] is False


def test_out_of_trajectory_action_is_rejected_by_default() -> None:
    global_contract = _global()
    result = validate_tool_call_ifc_drift(
        _call("send_money", amount="50.0"),
        query="look up account",
        messages=[],
        initial_function_trajectory=[],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=_state(),
    )
    assert not result.allowed
    assert result.events[0]["decision"] == "reject"


def test_out_of_trajectory_action_can_request_replan_when_explicitly_enabled() -> None:
    global_contract = _global()
    result = validate_tool_call_ifc_drift(
        _call("send_money", amount="50.0"),
        query="pay invoice",
        messages=[],
        initial_function_trajectory=[],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=_state(),
        allow_action_replan=True,
    )
    assert not result.allowed
    assert result.events[0]["decision"] == "replan_required"


def test_read_output_not_authorized_for_action_by_default() -> None:
    global_contract = _global()
    state = IFCProvenanceState()
    state.add_record(IFCProvenanceRecord("50.0", {"search_web.output.amount"}, set(), {"structured_extraction"}, trust="TOOL_OUTPUT", source_path="search_web.output.amount"))
    result = validate_tool_call_ifc_drift(
        _call("send_money", amount="50.0"),
        query="pay invoice",
        messages=[],
        initial_function_trajectory=["send_money"],
        achieved_function_trajectory=[],
        global_contract=global_contract,
        task_flow_contract=_task(global_contract),
        provenance_state=state,
    )
    assert not result.allowed
    assert result.rejected_sink == "send_money.amount"
    assert "source_not_authorized" in result.reason
