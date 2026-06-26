from __future__ import annotations

import json

from pact_drift.argument_flow_validator import validate_tool_call_arguments_ifc
from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.ifc_provenance import IFCProvenanceRecord, IFCProvenanceState
from pact_drift.task_flow_contract import FlowBinding, TaskFlowContract


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _global():
    return generate_ifc_global_contract(
        [
            _schema("send_money", {"recipient": _arg(), "amount": {"type": "number"}, "subject": _arg(), "date": _arg()}),
            _schema("create_file", {"filename": _arg(), "content": _arg()}),
            _schema("post_webpage", {"url": _arg(), "content": _arg()}),
        ],
        "agentdojo",
        {"name": "agentdojo", "version": "v1"},
    )


def _task(global_contract, *bindings: FlowBinding):
    grouped = {}
    for binding in bindings:
        grouped.setdefault(binding.sink, []).append(binding)
    return TaskFlowContract(
        task_contract_version="pact_drift_ifc_task_v1",
        task_type="test",
        allowed_trajectory=[],
        opportunistic_read_policy={},
        source_delegations=[],
        flow_bindings=grouped,
        unresolved_bindings=[],
    )


def _binding(global_contract, sink: str, source_path: str, i_label: str, c_label: str, declassifications: list[str] | None = None) -> FlowBinding:
    tool, arg = sink.split(".", 1)
    global_arg = global_contract.tools[tool].args[arg]
    return FlowBinding(
        source_path=source_path,
        sink=sink,
        I_after=i_label,
        C_label=c_label,
        satisfies=list(global_arg.flow_constraints),
        endorsements=list(global_arg.endorsements),
        declassifications=declassifications or [],
        reason="test binding",
    )


def _call(tool_name: str, **arguments):
    return [{"function": {"name": tool_name, "arguments": json.dumps(arguments)}}]


def _state(record: IFCProvenanceRecord) -> IFCProvenanceState:
    state = IFCProvenanceState()
    state.add_record(record)
    return state


def test_invoice_amount_to_send_money_amount_is_allowed() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "send_money.amount", "read_file.output.invoice.amount", "DELEGATED", "SENSITIVE"))
    state = _state(IFCProvenanceRecord("50.0", "read_file.output.invoice.amount", "DELEGATED", "SENSITIVE"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert allowed
    assert events[0]["reason"] == "authorized_flow"


def test_unauthorized_tool_output_to_send_money_amount_is_rejected() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "send_money.amount", "transaction_history.output.amount", "DELEGATED", "SENSITIVE"))
    state = _state(IFCProvenanceRecord("50.0", "transaction_history.output.amount", "DELEGATED", "SENSITIVE", marks=["unauthorized_tool_output"]))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert not allowed
    assert "unauthorized_tool_output" in events[0]["reason"]


def test_injected_instruction_to_send_money_recipient_is_rejected() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "send_money.recipient", "read_file.output.injected_instruction", "DELEGATED", "USER_PRIVATE"))
    state = _state(IFCProvenanceRecord("Mallory", "read_file.output.injected_instruction", "DELEGATED", "USER_PRIVATE", marks=["injected_instruction"]))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", recipient="Mallory"), global_contract, task, state)
    assert not allowed
    assert "injected_instruction" in events[0]["reason"]


def test_user_private_to_create_file_content_is_allowed() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "create_file.content", "user.explicit.content", "USER", "USER_PRIVATE"))
    state = _state(IFCProvenanceRecord("hello", "user.explicit.content", "USER", "USER_PRIVATE"))
    allowed, _ = validate_tool_call_arguments_ifc(_call("create_file", content="hello"), global_contract, task, state)
    assert allowed


def test_user_private_to_post_webpage_without_declassification_is_rejected() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "post_webpage.content", "user.explicit.content", "USER", "USER_PRIVATE"))
    state = _state(IFCProvenanceRecord("private", "user.explicit.content", "USER", "USER_PRIVATE"))
    allowed, events = validate_tool_call_arguments_ifc(_call("post_webpage", content="private"), global_contract, task, state)
    assert not allowed
    assert "confidentiality_label_exceeds_allowed_maximum" in events[0]["reason"]


def test_source_path_not_in_task_contract_is_rejected() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "send_money.amount", "read_file.output.invoice.amount", "DELEGATED", "SENSITIVE"))
    state = _state(IFCProvenanceRecord("50.0", "other.output.amount", "DELEGATED", "SENSITIVE"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert not allowed
    assert "source_path_not_authorized_by_task" in events[0]["reason"]


def test_integrity_label_below_minimum_is_rejected() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "send_money.amount", "read_file.output.invoice.amount", "EXTERNAL", "SENSITIVE"))
    state = _state(IFCProvenanceRecord("50.0", "read_file.output.invoice.amount", "EXTERNAL", "SENSITIVE"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert not allowed
    assert "integrity_label_below_required_minimum" in events[0]["reason"]


def test_confidentiality_label_above_max_without_declassification_is_rejected() -> None:
    global_contract = _global()
    task = _task(global_contract, _binding(global_contract, "create_file.content", "user.explicit.content", "USER", "SENSITIVE"))
    state = _state(IFCProvenanceRecord("secret", "user.explicit.content", "USER", "SENSITIVE"))
    allowed, events = validate_tool_call_arguments_ifc(_call("create_file", content="secret"), global_contract, task, state)
    assert not allowed
    assert "confidentiality_label_exceeds_allowed_maximum" in events[0]["reason"]
