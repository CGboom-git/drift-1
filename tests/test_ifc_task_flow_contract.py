from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.task_flow_contract import (
    TASK_CONTRACT_VERSION,
    validate_task_flow_contract_schema,
)
from pact_drift.task_flow_contract_generator import deterministic_task_flow_contract, extract_explicit_user_fields, summarize_task_flow_contract


def _schema(name: str, properties: dict[str, dict], description: str = "", output_properties: dict[str, dict] | None = None) -> dict:
    schema = {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}
    if output_properties is not None:
        schema["output_schema"] = {"type": "object", "properties": output_properties}
    return schema


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _tool_schemas(output_properties: dict[str, dict] | None = None):
    return [
        _schema("read_doc", {"file_path": _arg("document file path")}, "Read a document file.", output_properties),
        _schema("pay_tool", {"amount": {"type": "number"}, "recipient": _arg()}, "Pay a value."),
        _schema("write_tool", {"content": _arg("content to write")}, "Write content."),
    ]


def _global(output_properties: dict[str, dict] | None = None):
    contract = generate_ifc_global_contract(
        _tool_schemas(output_properties),
        "generic",
        {"name": "generic", "version": "v1"},
    )
    contract.tools["write_tool"].args["content"].sink_role = "content"
    contract.tools["write_tool"].args["content"].flow_constraints = ["non_instructional_content", "task_relevance"]
    contract.tools["write_tool"].args["content"].endorsements = ["task_delegation", "structured_extraction", "schema_validated_parse", "exact_match_to_authorized_source"]
    return contract


def _contract():
    return {
        "task_contract_version": TASK_CONTRACT_VERSION,
        "task_type": "read_to_action_flow",
        "allowed_trajectory": ["read_doc", "pay_tool"],
        "opportunistic_read_policy": {
            "READ_LOW": "allow_and_track",
            "READ_SENSITIVE": "allow_and_quarantine_unless_task_delegated",
            "output_can_flow_to_action_by_default": False,
        },
        "source_delegations": [],
        "flow_bindings": {
            "pay_tool.amount": [
                {
                    "source_path": "read_doc.output.amount",
                    "sink": "pay_tool.amount",
                    "I_after": "DELEGATED",
                    "C_label": "SENSITIVE",
                    "satisfies": ["authorized_control_value", "structured_source_required"],
                    "endorsements": ["task_delegation", "structured_extraction"],
                    "declassifications": [],
                    "reason": "amount is delegated by the task",
                }
            ]
        },
        "unresolved_bindings": [
            {
                "sink": "pay_tool.recipient",
                "required_constraints": ["authorized_destination"],
                "reason": "recipient is missing",
                "policy": "safe_refusal",
            }
        ],
        "missing_required_field": "safe_refusal",
    }


def test_task_flow_contract_accepts_authorized_subset_and_unresolved_binding() -> None:
    validate_task_flow_contract_schema(_contract(), _global({"amount": {"type": "number"}}))


def test_task_flow_contract_rejects_global_policy_fields() -> None:
    data = _contract()
    data["flow_bindings"]["pay_tool.amount"][0]["I_min"] = "EXTERNAL"
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global({"amount": {"type": "number"}})))


def test_task_flow_contract_rejects_constraints_outside_global_sink() -> None:
    data = _contract()
    data["flow_bindings"]["pay_tool.amount"][0]["satisfies"].append("authorized_destination")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global({"amount": {"type": "number"}})))


def test_task_flow_contract_rejects_endorsements_outside_global_sink() -> None:
    data = _contract()
    data["flow_bindings"]["pay_tool.amount"][0]["endorsements"].append("trusted_tool_derivation")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global({"amount": {"type": "number"}})))


def test_task_flow_contract_rejects_declassifications_outside_global_sink() -> None:
    data = _contract()
    data["flow_bindings"]["pay_tool.amount"][0]["declassifications"].append("destination_scope_match")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global({"amount": {"type": "number"}})))


def test_explicit_user_field_extractor_is_conservative() -> None:
    fields = extract_explicit_user_fields("Process the file report.txt.")
    assert "amount" not in fields
    assert "recipient" not in fields
    assert "date" not in fields


def test_no_unconditional_user_explicit_fallback() -> None:
    contract = deterministic_task_flow_contract("Process the file report.txt.", ["pay_tool"], _global({"amount": {"type": "number"}}))
    assert "pay_tool.amount" not in contract.flow_bindings
    assert "pay_tool.amount" in {binding.sink for binding in contract.unresolved_bindings}


def test_deterministic_fallback_allows_only_explicit_query_fields() -> None:
    contract = deterministic_task_flow_contract("Pay Alice 50 dollars tomorrow.", ["pay_tool"], _global({"amount": {"type": "number"}}))
    assert contract.allowed_paths_for_sink("pay_tool.recipient") == ["user.explicit.recipient"]
    assert contract.allowed_paths_for_sink("pay_tool.amount") == ["user.explicit.amount"]
    assert "pay_tool.amount" not in {binding.sink for binding in contract.unresolved_bindings}


def test_summary_contains_allowed_source_paths() -> None:
    output_properties = {"amount": {"type": "number", "description": "amount from the document"}}
    contract = deterministic_task_flow_contract("Use report.txt to process the amount.", ["read_doc", "pay_tool"], _global(output_properties), tool_schemas=_tool_schemas(output_properties))
    summary = summarize_task_flow_contract(contract)
    assert summary["flow_bindings"]["pay_tool.amount"][0]["source_path"] == "read_doc.output.amount"
    assert "flow_binding_sinks" not in summary
    assert "unresolved_sinks" not in summary


def test_generic_fallback_matches_control() -> None:
    output_properties = {"amount": {"type": "number", "description": "amount from the document"}}
    contract = deterministic_task_flow_contract("Use report.txt to process the amount.", ["read_doc", "pay_tool"], _global(output_properties), tool_schemas=_tool_schemas(output_properties))
    assert contract.allowed_paths_for_sink("pay_tool.amount") == ["read_doc.output.amount"]


def test_generic_fallback_matches_content() -> None:
    output_properties = {"summary": {"type": "string", "description": "short textual summary"}}
    contract = deterministic_task_flow_contract("Use report.txt to write the summary.", ["read_doc", "write_tool"], _global(output_properties), tool_schemas=_tool_schemas(output_properties))
    assert contract.allowed_paths_for_sink("write_tool.content") == ["read_doc.output.summary"]


def test_ambiguous_candidate_goes_unresolved() -> None:
    output_properties = {"amount": {"type": "number"}}
    schemas = [
        _schema("read_alpha", {"file_path": _arg("document file path")}, "Read a document file.", output_properties),
        _schema("read_beta", {"file_path": _arg("document file path")}, "Read a document file.", output_properties),
        _schema("pay_tool", {"amount": {"type": "number"}}, "Pay a value."),
    ]
    contract = generate_ifc_global_contract(schemas, "generic", {"name": "generic", "version": "v1"})
    task = deterministic_task_flow_contract("Use report.txt to process the amount.", ["read_alpha", "read_beta", "pay_tool"], contract, tool_schemas=schemas)
    assert "pay_tool.amount" not in task.flow_bindings
    assert "pay_tool.amount" in {binding.sink for binding in task.unresolved_bindings}


def test_task_type_is_not_benchmark_specific() -> None:
    output_properties = {"amount": {"type": "number"}}
    contract = deterministic_task_flow_contract("Use report.txt to process the amount.", ["read_doc", "pay_tool"], _global(output_properties), tool_schemas=_tool_schemas(output_properties))
    assert contract.task_type == "read_to_action_flow"
    assert contract.task_type != "banking_payment"


def _expect_value_error(callback) -> None:
    try:
        callback()
    except ValueError:
        return
    raise AssertionError("expected ValueError")
