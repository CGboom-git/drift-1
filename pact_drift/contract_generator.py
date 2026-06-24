from __future__ import annotations

from typing import Any

from pact_drift.contracts import ArgumentContract, GlobalToolContracts, ToolContract
from pact_drift.schema_utils import compute_schema_hash, compute_tool_schema_hash

_ACTION_PREFIXES = ("send_", "transfer", "pay", "delete", "update", "create", "book", "schedule", "write", "execute", "cancel")
_SENSITIVE_MARKERS = ("iban", "balance", "transaction", "account", "file", "email", "contact", "profile")


def _action_argument_contract(name: str) -> ArgumentContract:
    roles = {
        "recipient": "target", "amount": "financial_amount", "subject": "content_safety_critical", "date": "control",
        "path": "target", "file_path": "target", "command": "command", "credential": "credential",
    }
    role = roles.get(name, "content")
    strict = role in {"target", "command", "credential", "control", "financial_amount", "content_safety_critical"}
    forbidden = ["model_guess", "injected_instruction"]
    if strict:
        forbidden.extend(["untrusted_raw_text", "unrequested_transaction_history"])
    return ArgumentContract(role=role, allow_model_generated=not strict, forbidden_origins=forbidden)


def _heuristic_tool_contract(schema: dict[str, Any]) -> ToolContract:
    name = schema["name"]
    lower_name = name.lower()
    parameter_names = schema.get("parameters", {}).get("properties", {}).keys()
    if lower_name.startswith(_ACTION_PREFIXES):
        return ToolContract(
            tool_name=name,
            tool_type="ACTION",
            check_mode="full",
            arguments={argument: _action_argument_contract(argument) for argument in parameter_names},
            output_policy={"raw_output_trust": "TOOL_OUTPUT"},
            description="State-changing tool; validate control flow and argument provenance.",
        )
    if any(marker in lower_name for marker in _SENSITIVE_MARKERS):
        return ToolContract(
            tool_name=name,
            tool_type="READ_SENSITIVE",
            check_mode="control_check_and_track",
            output_policy={
                "raw_output_trust": "EXTERNAL" if name == "read_file" else "TOOL_OUTPUT",
                "requires_structured_extraction": name == "read_file",
                "propagate_input_origins": name == "get_iban",
            },
            description="Read tool with potentially sensitive or untrusted output.",
        )
    return ToolContract(tool_name=name, tool_type="READ_LOW", check_mode="track_only", output_policy={"raw_output_trust": "TOOL_OUTPUT"})


def generate_global_tool_contracts(tool_schemas: list[dict[str, Any]], client: Any | None = None, model_name: str = "offline", prompt_version: str = "tool_contract_prompt_v1") -> GlobalToolContracts:
    """Create a frozen, auditable contract once from complete schemas.

    The initial implementation is deterministic to keep an offline build reproducible. A caller may
    review and edit the JSON contract before freezing it for experiments.
    """
    del client
    tools = {schema["name"]: _heuristic_tool_contract(schema) for schema in tool_schemas}
    return GlobalToolContracts(
        contract_version="pact-drift-v1",
        schema_hash=compute_schema_hash(tool_schemas),
        generated_by={"mode": "offline_heuristic", "model": model_name, "prompt_version": prompt_version},
        tools=tools,
        tool_schema_hashes={schema["name"]: compute_tool_schema_hash(schema) for schema in tool_schemas},
    )
