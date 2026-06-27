from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.ifc_provenance import IFCProvenanceRecord, IFCProvenanceState, extract_ifc_structured_fields, flatten_tool_output, merge_provenance, record_tool_output_ifc, record_user_explicit_fields_ifc


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
            _schema("get_iban", {"recipient": _arg()}, "Look up IBAN."),
        ],
        "agentdojo",
        {"name": "agentdojo", "version": "v1"},
    )


def test_raw_external_read_file_is_marked_for_structured_extraction() -> None:
    state = IFCProvenanceState()
    record_tool_output_ifc("read_file", {}, "Amount: 50.0", _global(), None, state, in_planned_trajectory=True)
    raw = state.find_by_path("read_file.output.raw")
    assert raw.trust == "EXTERNAL"
    assert "raw_external_content" in raw.marks
    assert raw.authorized_for_action_flow is False


def test_structured_extraction_records_runtime_proofs() -> None:
    records = extract_ifc_structured_fields("Amount: 50.0", None)
    amount = next(record for record in records if record.source_path == "read_file.output.invoice.amount")
    assert amount.trust == "DELEGATED"
    assert "structured_extraction" in amount.proofs
    assert "raw_external_content" not in amount.marks


def test_out_of_trajectory_read_sensitive_is_quarantined() -> None:
    state = IFCProvenanceState()
    record_tool_output_ifc("get_most_recent_transactions", {}, "[]", _global(), None, state, in_planned_trajectory=False)
    raw = state.find_by_path("get_most_recent_transactions.output.raw")
    assert raw.trust == "TOOL_OUTPUT"
    assert "unauthorized_tool_output" in raw.marks
    assert raw.authorized_for_action_flow is False


def test_flatten_tool_output_records_common_email_fields() -> None:
    records = flatten_tool_output("get_received_emails", [{"id": "e1", "from": "alice@example.com", "subject": "Hello", "body": "Hi"}])
    by_path = {record.source_path: record for record in records}
    assert by_path["get_received_emails.output.email_id"].value == "e1"
    assert by_path["get_received_emails.output.email_id"].proofs == {"structured_extraction"}
    assert by_path["get_received_emails.output.sender"].value == "alice@example.com"
    assert by_path["get_received_emails.output.subject"].value == "Hello"
    assert by_path["get_received_emails.output.body"].value == "Hi"


def test_record_user_explicit_fields_adds_user_explicit_proof() -> None:
    state = IFCProvenanceState()
    record_user_explicit_fields_ifc("Pay Alice 50 dollars tomorrow.", None, state)
    record = state.find_by_path("user.explicit.amount")
    assert record is not None
    assert record.proofs == {"user_explicit"}
    assert record.trust == "USER"


def test_record_tool_output_adds_trusted_derivation() -> None:
    state = IFCProvenanceState()
    state.add_record(IFCProvenanceRecord("DE89", {"user.explicit.recipient"}, set(), {"user_explicit"}, trust="USER", metadata={}, source_path="user.explicit.recipient"))
    record_tool_output_ifc("get_iban", {"recipient": "DE89"}, {"iban": "DE89"}, _global(), None, state, in_planned_trajectory=True)
    iban = state.find_by_path("get_iban.output.iban")
    assert "trusted_tool_derivation" in iban.proofs


def test_merge_provenance_unions_source_paths_marks_and_proofs() -> None:
    merged = merge_provenance(
        [
            IFCProvenanceRecord("50.0", {"read_file.output.amount"}, {"raw_external_content"}, {"structured_extraction"}, trust="DELEGATED", metadata={}, source_path="read_file.output.amount"),
            IFCProvenanceRecord("50.0", {"user.explicit.amount"}, set(), {"user_explicit"}, trust="USER", metadata={}, source_path="user.explicit.amount"),
        ]
    )
    assert merged.source_paths == {"read_file.output.amount", "user.explicit.amount"}
    assert merged.marks == {"raw_external_content"}
    assert merged.proofs == {"structured_extraction", "user_explicit"}
    assert merged.trust == "DELEGATED"
