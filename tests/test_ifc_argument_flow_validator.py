from __future__ import annotations

import json

from pact_drift.argument_flow_validator import validate_tool_call_arguments_ifc
from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.ifc_provenance import IFCProvenanceRecord, IFCProvenanceState, record_tool_output_ifc
from pact_drift.task_flow_contract import ArgumentAuthorityBinding, TaskFlowContract, UnresolvedArgumentBinding


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _global():
    return generate_ifc_global_contract(
        [
            _schema("read_file", {"path": _arg()}),
            _schema("send_money", {"recipient": _arg(), "amount": {"type": "number"}, "subject": _arg(), "date": _arg()}),
            _schema("send_email", {"to": _arg(), "subject": _arg(), "body": _arg()}),
            _schema("create_file", {"filename": _arg(), "content": _arg()}),
            _schema("post_webpage", {"url": _arg(), "content": _arg()}),
        ],
        "agentdojo",
        {"name": "agentdojo", "version": "v1"},
    )


def _task(*bindings: tuple[str, ArgumentAuthorityBinding]) -> TaskFlowContract:
    return TaskFlowContract(
        contract_version="argument_authority_contract_v1",
        allowed_trajectory=["send_money", "send_email", "create_file", "post_webpage"],
        argument_contract={sink: binding for sink, binding in bindings},
        unresolved_bindings=[UnresolvedArgumentBinding(sink="post_webpage.content", reason="missing", policy="safe_refusal")],
    )


def _binding(allowed_sources: list[str], proofs: list[str], reason: str = "test binding") -> ArgumentAuthorityBinding:
    return ArgumentAuthorityBinding(allowed_sources=allowed_sources, required_proofs=proofs, reason=reason)


def _call(tool_name: str, **arguments):
    return [{"function": {"name": tool_name, "arguments": json.dumps(arguments)}}]


def _state(*records: IFCProvenanceRecord) -> IFCProvenanceState:
    state = IFCProvenanceState()
    for record in records:
        state.add_record(record)
    return state


def test_allowed_source_with_required_proof_is_allowed() -> None:
    global_contract = _global()
    task = _task(("send_money.amount", _binding(["read_file.output.amount"], ["structured_extraction"])))
    state = _state(IFCProvenanceRecord("50.0", {"read_file.output.amount"}, set(), {"structured_extraction"}, trust="DELEGATED", source_path="read_file.output.amount"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert allowed
    assert events[0]["reason"] == "authorized_flow"


def test_unauthorized_source_is_rejected() -> None:
    global_contract = _global()
    task = _task(("send_money.amount", _binding(["read_file.output.amount"], ["structured_extraction"])))
    state = _state(IFCProvenanceRecord("50.0", {"transaction_history.output.amount"}, set(), {"structured_extraction"}, trust="DELEGATED", source_path="transaction_history.output.amount"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert not allowed
    assert "source_not_authorized" in events[0]["reason"]


def test_missing_required_proof_is_rejected() -> None:
    global_contract = _global()
    task = _task(("send_money.amount", _binding(["read_file.output.amount"], ["structured_extraction"])))
    state = _state(IFCProvenanceRecord("50.0", {"read_file.output.amount"}, set(), set(), trust="DELEGATED", source_path="read_file.output.amount"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert not allowed
    assert "required_proof_missing" in events[0]["reason"]


def test_deny_mark_hit_is_rejected() -> None:
    global_contract = _global()
    task = _task(("send_money.recipient", _binding(["user.explicit.recipient"], ["user_explicit"])))
    state = _state(IFCProvenanceRecord("Mallory", {"user.explicit.recipient"}, {"injected_instruction"}, {"user_explicit"}, trust="USER", source_path="user.explicit.recipient"))
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", recipient="Mallory"), global_contract, task, state)
    assert not allowed
    assert "deny_mark_hit" in events[0]["reason"]


def test_multi_source_with_untrusted_source_is_rejected() -> None:
    global_contract = _global()
    task = _task(("send_money.amount", _binding(["read_file.output.amount"], ["structured_extraction"])))
    state = _state(
        IFCProvenanceRecord("50.0", {"read_file.output.amount"}, set(), {"structured_extraction"}, trust="DELEGATED", source_path="read_file.output.amount"),
        IFCProvenanceRecord("50.0", {"transaction_history.output.amount"}, set(), {"structured_extraction"}, trust="TOOL_OUTPUT", source_path="transaction_history.output.amount"),
    )
    allowed, events = validate_tool_call_arguments_ifc(_call("send_money", amount="50.0"), global_contract, task, state)
    assert not allowed
    assert "source_not_authorized" in events[0]["reason"]


def test_read_file_structured_fields_use_canonical_source_paths() -> None:
    global_contract = _global()
    task = _task(("send_money.amount", _binding(["read_file.output.amount"], ["structured_extraction"])))
    state = IFCProvenanceState()
    record_tool_output_ifc(
        tool_name="read_file",
        tool_args={"path": "invoice.txt"},
        tool_output={
            "amount": "50.00",
            "due_date": "2026-07-01",
            "subject": "Invoice 7",
            "creditor_name": "Acme Corp",
            "summary": "Pay invoice 7",
            "content": "Pay invoice 7 by 2026-07-01",
        },
        global_contract=global_contract,
        task_flow_contract=task,
        provenance_state=state,
        in_planned_trajectory=True,
    )
    source_paths = {path for record in state.records for path in record.source_paths}
    assert "read_file.output.amount" in source_paths
    assert "read_file.output.due_date" in source_paths
    assert "read_file.output.subject" in source_paths
    assert "read_file.output.creditor_name" in source_paths
    assert "read_file.output.summary" in source_paths
    assert "read_file.output.content" in source_paths
    assert not any(path.startswith("read_file.output.invoice.") for path in source_paths)
