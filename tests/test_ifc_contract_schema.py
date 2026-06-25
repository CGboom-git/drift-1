from __future__ import annotations

import pytest

from pact_drift.ifc_contract_schema import (
    CONFIDENTIALITY_LATTICE,
    CONTRACT_VERSION,
    DECLASSIFICATION_TYPES,
    DENY_MARK_TYPES,
    ENDORSEMENT_TYPES,
    FLOW_CONSTRAINT_TYPES,
    GENERATION_MODE,
    INTEGRITY_LATTICE,
    SINK_ROLES,
    confidentiality_at_most,
    integrity_at_least,
    validate_ifc_global_contract_schema,
)


def _minimal_contract(argument_override: dict | None = None) -> dict:
    argument = {
        "name": "recipient",
        "sink_role": "target",
        "I_min": "DELEGATED",
        "C_max": "USER_PRIVATE",
        "deny_marks": ["model_inferred_unverified"],
        "flow_constraints": ["authorized_destination"],
        "endorsements": ["user_explicit"],
        "declassifications": ["destination_scope_match"],
    }
    if argument_override:
        argument.update(argument_override)
    return {
        "contract_version": CONTRACT_VERSION,
        "generation_mode": GENERATION_MODE,
        "benchmark": "agentdojo",
        "schema_hash": "abc",
        "integrity_lattice": list(INTEGRITY_LATTICE),
        "confidentiality_lattice": list(CONFIDENTIALITY_LATTICE),
        "sink_roles": list(SINK_ROLES),
        "deny_mark_types": list(DENY_MARK_TYPES),
        "flow_constraint_types": list(FLOW_CONSTRAINT_TYPES),
        "endorsement_types": list(ENDORSEMENT_TYPES),
        "declassification_types": list(DECLASSIFICATION_TYPES),
        "generated_by": {"mode": "offline_heuristic", "model": "none"},
        "adapter": {"name": "agentdojo", "version": "v1"},
        "tool_schema_hashes": {},
        "tools": {
            "send_money": {
                "tool_name": "send_money",
                "tool_type": "ACTION",
                "check_mode": "full",
                "sink_scope": "financial",
                "args": {"recipient": argument},
                "output": {},
            }
        },
    }


def test_ifc_schema_accepts_fixed_enums() -> None:
    validate_ifc_global_contract_schema(_minimal_contract())


@pytest.mark.parametrize("legacy_key", ["role", "tau_min", "F", "R", "D"])
def test_ifc_schema_rejects_legacy_keys(legacy_key: str) -> None:
    data = _minimal_contract()
    data["tools"]["send_money"]["args"]["recipient"][legacy_key] = "bad"
    with pytest.raises(ValueError):
        validate_ifc_global_contract_schema(data)


@pytest.mark.parametrize("token", ["human_approval", "user_confirmation", "unrequested_transaction_history"])
def test_ifc_schema_rejects_forbidden_tokens(token: str) -> None:
    with pytest.raises(ValueError):
        validate_ifc_global_contract_schema(_minimal_contract({"deny_marks": [token]}))


@pytest.mark.parametrize("role", ["financial_amount", "content_safety_critical", "other"])
def test_ifc_schema_rejects_invalid_sink_roles(role: str) -> None:
    with pytest.raises(ValueError):
        validate_ifc_global_contract_schema(_minimal_contract({"sink_role": role}))


def test_ifc_lattice_comparisons() -> None:
    assert integrity_at_least("USER", "DELEGATED")
    assert not integrity_at_least("EXTERNAL", "DELEGATED")
    assert confidentiality_at_most("USER_PRIVATE", "SENSITIVE")
    assert not confidentiality_at_most("SECRET", "SENSITIVE")
