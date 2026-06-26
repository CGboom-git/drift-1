from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.task_flow_contract import (
    TASK_CONTRACT_VERSION,
    validate_task_flow_contract_schema,
)
from pact_drift.task_flow_contract_generator import deterministic_task_flow_contract, extract_explicit_user_fields


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _global():
    return generate_ifc_global_contract(
        [_schema("send_money", {"amount": {"type": "number"}, "recipient": _arg(), "date": _arg()})],
        "agentdojo",
        {"name": "agentdojo", "version": "v1"},
    )


def _contract():
    return {
        "task_contract_version": TASK_CONTRACT_VERSION,
        "task_type": "banking_payment",
        "allowed_trajectory": ["read_file", "send_money"],
        "opportunistic_read_policy": {
            "READ_LOW": "allow_and_track",
            "READ_SENSITIVE": "allow_and_quarantine_unless_task_delegated",
            "output_can_flow_to_action_by_default": False,
        },
        "source_delegations": [],
        "flow_bindings": {
            "send_money.amount": [
                {
                    "source_path": "read_file.output.invoice.amount",
                    "sink": "send_money.amount",
                    "I_after": "DELEGATED",
                    "C_label": "SENSITIVE",
                    "satisfies": ["authorized_control_value", "structured_source_required"],
                    "endorsements": ["task_delegation", "structured_extraction"],
                    "declassifications": [],
                    "reason": "invoice amount is delegated by the task",
                }
            ]
        },
        "unresolved_bindings": [
            {
                "sink": "send_money.recipient",
                "required_constraints": ["authorized_destination"],
                "reason": "recipient is missing",
                "policy": "safe_refusal",
            }
        ],
        "missing_required_field": "safe_refusal",
    }


def test_task_flow_contract_accepts_authorized_subset_and_unresolved_binding() -> None:
    validate_task_flow_contract_schema(_contract(), _global())


def test_task_flow_contract_rejects_global_policy_fields() -> None:
    data = _contract()
    data["flow_bindings"]["send_money.amount"][0]["I_min"] = "EXTERNAL"
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global()))


def test_task_flow_contract_rejects_constraints_outside_global_sink() -> None:
    data = _contract()
    data["flow_bindings"]["send_money.amount"][0]["satisfies"].append("authorized_destination")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global()))


def test_task_flow_contract_rejects_endorsements_outside_global_sink() -> None:
    data = _contract()
    data["flow_bindings"]["send_money.amount"][0]["endorsements"].append("trusted_tool_derivation")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global()))


def test_task_flow_contract_rejects_declassifications_outside_global_sink() -> None:
    data = _contract()
    data["flow_bindings"]["send_money.amount"][0]["declassifications"].append("destination_scope_match")
    _expect_value_error(lambda: validate_task_flow_contract_schema(data, _global()))


def test_explicit_user_field_extractor_is_conservative() -> None:
    fields = extract_explicit_user_fields("Pay the bill in invoice.txt.")
    assert "amount" not in fields
    assert "recipient" not in fields
    assert "date" not in fields


def test_deterministic_fallback_does_not_invent_user_explicit_amount() -> None:
    contract = deterministic_task_flow_contract("Pay the bill in invoice.txt.", ["send_money"], _global())
    assert "send_money.amount" not in contract.flow_bindings
    assert "send_money.amount" in {binding.sink for binding in contract.unresolved_bindings}


def test_deterministic_fallback_allows_only_explicit_query_fields() -> None:
    contract = deterministic_task_flow_contract("Pay Alice 50 dollars tomorrow.", ["send_money"], _global())
    assert contract.allowed_paths_for_sink("send_money.recipient") == ["user.explicit.recipient"]
    assert contract.allowed_paths_for_sink("send_money.amount") == ["user.explicit.amount"]
    assert contract.allowed_paths_for_sink("send_money.date") == ["user.explicit.date"]
    assert "send_money.amount" not in {binding.sink for binding in contract.unresolved_bindings}


def _expect_value_error(callback) -> None:
    try:
        callback()
    except ValueError:
        return
    raise AssertionError("expected ValueError")
