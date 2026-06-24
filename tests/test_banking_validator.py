from types import SimpleNamespace

from pact_drift.contract_generator import generate_global_tool_contracts
from pact_drift.provenance import ProvenanceRecord, ProvenanceState
from pact_drift.task_contract import generate_task_contract
from pact_drift.validator import validate_tool_call_arguments


def _contracts():
    return generate_global_tool_contracts([{"name": "send_money", "description": "", "parameters": {"properties": {"recipient": {}, "amount": {}, "subject": {}, "date": {}}}}])


def _call(**arguments):
    import json
    return [{"function": {"name": "send_money", "arguments": json.dumps(arguments)}}]


def _valid_state():
    state = ProvenanceState()
    state.add_record(ProvenanceRecord("ACME Corp", "DELEGATED_TASK_DATA", [], source_path="read_file.output.invoice.creditor_name"))
    state.add_record(ProvenanceRecord("DE89", "DELEGATED_TASK_DATA", [], derivation=[{"source_path": "read_file.output.invoice.creditor_name"}], source_path="get_iban.output.iban"))
    state.add_record(ProvenanceRecord("150.00", "DELEGATED_TASK_DATA", [], source_path="read_file.output.invoice.amount"))
    state.add_record(ProvenanceRecord("December bill", "DELEGATED_TASK_DATA", [], source_path="read_file.output.invoice.subject"))
    state.add_record(ProvenanceRecord("2023-12-01", "DELEGATED_TASK_DATA", [], source_path="read_file.output.invoice.due_date"))
    return state


def test_valid_read_file_get_iban_send_money_chain_is_allowed():
    contracts = _contracts()
    allowed, events = validate_tool_call_arguments(_call(recipient="DE89", amount="150.00", subject="December bill", date="2023-12-01"), contracts, generate_task_contract("pay invoice", ["read_file", "get_iban", "send_money"], contracts, []), _valid_state(), SimpleNamespace())
    assert allowed
    assert {event["decision"] for event in events} == {"allow"}


def test_model_guessed_amount_and_today_are_rejected_even_when_control_flow_is_valid():
    contracts = _contracts()
    state = _valid_state()
    allowed, events = validate_tool_call_arguments(_call(recipient="DE89", amount="100.00", subject="December bill", date="today"), contracts, generate_task_contract("pay invoice", ["read_file", "get_iban", "send_money"], contracts, []), state, SimpleNamespace())
    assert not allowed
    assert any(event["argument"] == "amount" and event["decision"] == "reject" for event in events)
    assert any(event["argument"] == "date" and event["decision"] == "reject" for event in events)


def test_unrequested_transaction_history_recipient_is_rejected():
    contracts = _contracts()
    state = _valid_state()
    state.add_record(ProvenanceRecord("DE-ATTACK", "TOOL_OUTPUT", [], forbidden_marks=["unrequested_transaction_history"], source_path="transaction_history.output.recipient"))
    allowed, events = validate_tool_call_arguments(_call(recipient="DE-ATTACK", amount="150.00", subject="December bill", date="2023-12-01"), contracts, generate_task_contract("pay invoice", [], contracts, []), state, SimpleNamespace())
    assert not allowed
    assert any("unrequested_transaction_history" in event["reason"] for event in events)
