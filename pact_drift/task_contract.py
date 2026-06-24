from __future__ import annotations

from typing import Any

from pact_drift.contracts import GlobalToolContracts, TaskArgumentConstraint, TaskContract


def _banking_contract(allowed_trajectory: list[str]) -> TaskContract:
    trajectory = allowed_trajectory or ["read_file", "get_iban", "send_money"]
    return TaskContract(
        allowed_trajectory=trajectory,
        task_delegation={
            "delegated_source": "read_file(invoice)",
            "delegated_fields": ["invoice.creditor_name", "invoice.amount", "invoice.subject", "invoice.due_date"],
            "allowed_sink": "send_money",
            "requires_structured_extraction": True,
        },
        argument_source_constraints={
            "send_money.recipient": TaskArgumentConstraint("get_iban.output.iban", "read_file.output.invoice.creditor_name", forbidden_sources=["model_guess", "injected_instruction", "untrusted_raw_text", "unrequested_transaction_history"]),
            "send_money.amount": TaskArgumentConstraint("read_file.output.invoice.amount", forbidden_sources=["model_guess", "injected_instruction", "untrusted_raw_text", "unrequested_transaction_history"]),
            "send_money.subject": TaskArgumentConstraint("read_file.output.invoice.subject", forbidden_sources=["model_guess", "injected_instruction"]),
            "send_money.date": TaskArgumentConstraint("read_file.output.invoice.due_date", forbidden_sources=["model_guess", "injected_instruction", "current_date_default_without_user_authorization"]),
        },
    )


def generate_task_contract(user_task: str, allowed_trajectory: list[str], global_contracts: GlobalToolContracts, tool_schemas: list[dict[str, Any]], client: Any | None = None, model_name: str = "") -> TaskContract:
    """Generate task-level source constraints after the existing secure planner.

    Banking gets a deterministic, fail-closed contract in the first release. Other suites preserve
    their control-flow behavior and only receive an auditable empty argument contract.
    """
    del user_task, tool_schemas, client, model_name
    if "send_money" in global_contracts.tools or "send_money" in allowed_trajectory:
        return _banking_contract(allowed_trajectory)
    return TaskContract(allowed_trajectory=allowed_trajectory)
