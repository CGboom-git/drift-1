from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.task_flow_contract import TASK_CONTRACT_VERSION, validate_task_flow_contract_schema
from pact_drift.task_flow_contract_generator import deterministic_minimal_fallback, extract_explicit_user_fields, summarize_task_flow_contract


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _tool_schemas():
    return [
        _schema("read_doc", {"file_path": _arg("document file path")}, "Read a document file."),
        _schema("pay_tool", {"amount": {"type": "number"}, "recipient": _arg(), "subject": _arg(), "date": _arg()}, "Pay a value."),
        _schema("write_tool", {"content": _arg("content to write")}, "Write content."),
    ]


def _global():
    return generate_ifc_global_contract(
        _tool_schemas(),
        "generic",
        {"name": "generic", "version": "v1"},
    )


def _contract() -> dict:
    return {
        "contract_version": TASK_CONTRACT_VERSION,
        "allowed_trajectory": ["read_doc", "pay_tool"],
        "argument_contract": {
            "pay_tool.amount": {
                "allowed_sources": ["read_doc.output.amount"],
                "required_proofs": ["structured_extraction"],
                "reason": "amount is delegated by the task",
            },
            "pay_tool.recipient": {
                "allowed_sources": ["user.explicit.recipient"],
                "required_proofs": ["user_explicit"],
                "reason": "recipient is explicitly provided",
            },
        },
        "unresolved_bindings": [
            {
                "sink": "pay_tool.subject",
                "reason": "subject is missing",
                "policy": "safe_refusal",
            }
        ],
    }


def test_task_flow_contract_accepts_authorized_subset_and_unresolved_binding() -> None:
    validate_task_flow_contract_schema(_contract(), _global())


def test_task_flow_contract_rejects_global_policy_fields() -> None:
    data = _contract()
    data["argument_contract"]["pay_tool.amount"]["I_min"] = "EXTERNAL"
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global()))


def test_task_flow_contract_rejects_unsupported_required_proofs() -> None:
    data = _contract()
    data["argument_contract"]["pay_tool.amount"]["required_proofs"].append("not_a_real_proof")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global()))


def test_explicit_user_field_extractor_is_conservative() -> None:
    fields = extract_explicit_user_fields("Process the file report.txt.")
    assert "amount" not in fields
    assert "recipient" not in fields
    assert "date" not in fields


def test_deterministic_fallback_uses_only_explicit_values() -> None:
    contract = deterministic_minimal_fallback("Pay Alice 50 dollars tomorrow.", ["pay_tool"], _global())
    assert contract.allowed_sources_for_sink("pay_tool.amount") == ["user.explicit.amount"]
    assert contract.allowed_sources_for_sink("pay_tool.recipient") == ["user.explicit.recipient"]


def test_deterministic_fallback_leaves_missing_arguments_unresolved() -> None:
    contract = deterministic_minimal_fallback("Process the file report.txt.", ["read_doc", "pay_tool"], _global())
    assert contract.allowed_sources_for_sink("pay_tool.amount") == []
    assert "pay_tool.amount" in {binding.sink for binding in contract.unresolved_bindings}


def test_summary_contains_allowed_source_paths() -> None:
    contract = deterministic_minimal_fallback("Pay Alice 50 dollars tomorrow.", ["pay_tool"], _global())
    summary = summarize_task_flow_contract(contract)
    assert summary["argument_contract"]["pay_tool.amount"]["allowed_sources"] == ["user.explicit.amount"]
    assert summary["argument_contract"]["pay_tool.recipient"]["allowed_sources"] == ["user.explicit.recipient"]


def test_task_type_is_not_benchmark_specific() -> None:
    contract = deterministic_minimal_fallback("Use report.txt to process the amount.", ["read_doc", "pay_tool"], _global())
    assert contract.contract_version == "argument_authority_contract_v1"


def _expect_value_error(callback) -> None:
    try:
        callback()
    except ValueError:
        return
    raise AssertionError("expected ValueError")
