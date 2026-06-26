from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.ifc_provenance import IFCProvenanceState, extract_ifc_structured_fields, flatten_tool_output, record_tool_output_ifc


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _global():
    return generate_ifc_global_contract(
        [
            _schema("read_file", {"file_path": _arg()}, "Read a file."),
            _schema("get_most_recent_transactions", {"n": {"type": "integer"}}, "Read transaction history."),
            _schema("get_received_emails", {}, "Get received emails."),
        ],
        "agentdojo",
        {"name": "agentdojo", "version": "v1"},
    )


def test_raw_external_read_file_is_marked_for_structured_extraction() -> None:
    state = IFCProvenanceState()
    record_tool_output_ifc("read_file", {}, "Amount: 50.0", _global(), None, state, in_planned_trajectory=True)
    raw = state.find_by_path("read_file.output.raw")
    assert raw.I_label == "EXTERNAL"
    assert "raw_external_content" in raw.marks
    assert raw.authorized_for_action_flow is False


def test_structured_extraction_records_runtime_transformations() -> None:
    records = extract_ifc_structured_fields("Amount: 50.0", None)
    amount = next(record for record in records if record.source_path == "read_file.output.invoice.amount")
    assert amount.I_label == "DELEGATED"
    assert "structured_extraction" in amount.transformations
    assert "schema_validated_parse" in amount.transformations
    assert "raw_external_content" not in amount.marks


def test_out_of_trajectory_read_sensitive_is_quarantined() -> None:
    state = IFCProvenanceState()
    record_tool_output_ifc("get_most_recent_transactions", {}, "[]", _global(), None, state, in_planned_trajectory=False)
    raw = state.find_by_path("get_most_recent_transactions.output.raw")
    assert raw.I_label == "TOOL_OUTPUT"
    assert "unauthorized_tool_output" in raw.marks
    assert raw.authorized_for_action_flow is False


def test_flatten_tool_output_records_common_email_fields() -> None:
    records = flatten_tool_output("get_received_emails", [{"id": "e1", "from": "alice@example.com", "subject": "Hello", "body": "Hi"}])
    by_path = {record.source_path: record for record in records}
    assert by_path["get_received_emails.output.email_id"].value == "e1"
    assert by_path["get_received_emails.output.sender"].value == "alice@example.com"
    assert by_path["get_received_emails.output.subject"].value == "Hello"
    assert by_path["get_received_emails.output.body"].value == "Hi"


def test_record_tool_output_adds_flattened_records_without_action_authorization() -> None:
    state = IFCProvenanceState()
    record_tool_output_ifc("get_received_emails", {}, [{"id": "e1", "subject": "Hello"}], _global(), None, state, in_planned_trajectory=True)
    subject = state.find_by_path("get_received_emails.output.subject")
    assert subject is not None
    assert subject.I_label == "EXTERNAL"
    assert "raw_external_content" in subject.marks
    assert subject.authorized_for_action_flow is False
