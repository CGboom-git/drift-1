from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.task_flow_contract import (
    TASK_CONTRACT_VERSION,
    validate_task_flow_contract_schema,
)


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {"name": name, "description": description, "parameters": {"type": "object", "properties": properties}}


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _global():
    return generate_ifc_global_contract(
        [_schema("send_money", {"amount": {"type": "number"}, "recipient": _arg()})],
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


def _expect_value_error(callback) -> None:
    try:
        callback()
    except ValueError:
        return
    raise AssertionError("expected ValueError")
