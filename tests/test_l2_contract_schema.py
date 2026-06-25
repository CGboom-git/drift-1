from __future__ import annotations

import pytest

from pact_drift.contract_schema_l2 import (
    CONTRACT_VERSION,
    DISCHARGE_PROCEDURES,
    FORBIDDEN_ORIGIN_TYPES,
    GENERATION_MODE,
    OBLIGATION_TYPES,
    ROLES,
    TRUST_LATTICE,
    validate_l2_global_contracts_schema,
)


def _minimal_contract(argument_override: dict | None = None) -> dict:
    argument = {
        "name": "recipient",
        "role": "target",
        "tau_min": "DELEGATED",
        "F": ["model_guess"],
        "R": ["authorized_destination"],
        "D": ["user_explicit"],
    }
    if argument_override:
        argument.update(argument_override)
    return {
        "contract_version": CONTRACT_VERSION,
        "generation_mode": GENERATION_MODE,
        "schema_hash": "abc",
        "trust_lattice": list(TRUST_LATTICE),
        "roles": list(ROLES),
        "forbidden_origin_types": list(FORBIDDEN_ORIGIN_TYPES),
        "obligation_types": list(OBLIGATION_TYPES),
        "discharge_procedures": list(DISCHARGE_PROCEDURES),
        "generated_by": {"mode": "offline_heuristic", "model": "none"},
        "tools": {
            "send_money": {
                "tool_name": "send_money",
                "tool_type": "ACTION",
                "check_mode": "full",
                "args": {"recipient": argument},
                "output": {},
            }
        },
    }


def test_l2_schema_accepts_fixed_enums() -> None:
    validate_l2_global_contracts_schema(_minimal_contract())


@pytest.mark.parametrize("role", ["financial_amount", "content_safety_critical", "other"])
def test_l2_schema_rejects_invalid_roles(role: str) -> None:
    with pytest.raises(ValueError):
        validate_l2_global_contracts_schema(_minimal_contract({"role": role}))


def test_l2_schema_rejects_invalid_tau_min() -> None:
    with pytest.raises(ValueError):
        validate_l2_global_contracts_schema(_minimal_contract({"tau_min": "MODEL_GUESS"}))


def test_l2_schema_rejects_invalid_forbidden_origin() -> None:
    with pytest.raises(ValueError):
        validate_l2_global_contracts_schema(_minimal_contract({"F": ["model_guess", "freeform"]}))


def test_l2_schema_rejects_invalid_obligation() -> None:
    with pytest.raises(ValueError):
        validate_l2_global_contracts_schema(_minimal_contract({"R": ["task_relevance", "manual_review"]}))


@pytest.mark.parametrize("procedure", ["user_confirmation", "human_approval", "policy_allowlist", "none"])
def test_l2_schema_rejects_forbidden_discharge_procedures(procedure: str) -> None:
    with pytest.raises(ValueError):
        validate_l2_global_contracts_schema(_minimal_contract({"D": [procedure]}))
