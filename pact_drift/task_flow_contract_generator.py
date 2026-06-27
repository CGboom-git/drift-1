from __future__ import annotations

import json
import re
from typing import Any

try:
    from json_repair import repair_json
except ImportError:  # pragma: no cover - exercised only in minimal local environments.
    def repair_json(value: str) -> str:
        return value

from pact_drift.ifc_contract_schema import IFCGlobalContract, ifc_to_jsonable
from pact_drift.task_flow_contract import (
    TASK_CONTRACT_VERSION,
    ArgumentAuthorityBinding,
    TaskFlowContract,
    UnresolvedArgumentBinding,
    task_flow_contract_from_json,
)
from prompts import ARGUMENT_AUTHORITY_CONTRACT_PROMPT


def generate_task_flow_contract(
    user_query: str,
    initial_function_trajectory: list[str],
    tool_schemas: list[dict[str, Any]],
    global_contract: IFCGlobalContract,
    client: Any | None = None,
    model: str | None = None,
) -> TaskFlowContract:
    if client is not None:
        generated = _generate_with_client(
            user_query,
            initial_function_trajectory,
            tool_schemas,
            global_contract,
            client,
            model,
        )
        if generated is not None:
            return generated
    return deterministic_minimal_fallback(user_query, initial_function_trajectory, global_contract)


def deterministic_minimal_fallback(
    user_query: str,
    initial_function_trajectory: list[str],
    global_contract: IFCGlobalContract,
) -> TaskFlowContract:
    explicit_fields = extract_explicit_user_fields(user_query)
    argument_contract: dict[str, ArgumentAuthorityBinding] = {}
    unresolved_bindings: list[UnresolvedArgumentBinding] = []

    for tool_name in initial_function_trajectory:
        tool_contract = global_contract.tools.get(tool_name)
        if tool_contract is None or tool_contract.tool_type != "ACTION":
            continue
        for argument_name in tool_contract.args:
            sink = f"{tool_name}.{argument_name}"
            explicit_value = explicit_fields.get(argument_name)
            if explicit_value is not None:
                argument_contract[sink] = ArgumentAuthorityBinding(
                    allowed_sources=[f"user.explicit.{argument_name}"],
                    required_proofs=["user_explicit"],
                    reason="The value is explicitly provided in the original user task.",
                )
            else:
                unresolved_bindings.append(
                    UnresolvedArgumentBinding(
                        sink=sink,
                        reason="No reliable source path can be determined without LLM contract generation.",
                    )
                )

    contract = TaskFlowContract(
        contract_version=TASK_CONTRACT_VERSION,
        allowed_trajectory=list(initial_function_trajectory),
        argument_contract=argument_contract,
        unresolved_bindings=unresolved_bindings,
    )
    task_flow_contract_from_json(contract.to_json(), global_contract)
    return contract


def extract_explicit_user_fields(user_query: str) -> dict[str, Any]:
    """Conservatively extract authority-bearing values explicitly present in the user query."""
    fields: dict[str, Any] = {}
    query = user_query.strip()
    lower = query.lower()
    amount_match = re.search(r"(?i)(?:[$]\s*\d+(?:\.\d+)?|\b\d+(?:\.\d+)?\s*(?:dollars?|usd|eur|euros?|pounds?|gbp)\b)", query)
    if amount_match:
        number = re.search(r"\d+(?:\.\d+)?", amount_match.group(0))
        fields["amount"] = number.group(0) if number else amount_match.group(0).strip()
    date_match = re.search(
        r"(?i)\b(?:today|tomorrow|tonight|next\s+\w+|\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{2,4}|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b(?:\s+\d{1,2}(?:st|nd|rd|th)?)?",
        query,
    )
    if date_match:
        fields["date"] = date_match.group(0).strip()
    recipient_match = re.search(r"\b(?:[Pp]ay|[Ss]end|[Tt]ransfer)\s+(?:money\s+)?(?:to\s+)?([A-Z][A-Za-z0-9_.@-]*(?:\s+[A-Z][A-Za-z0-9_.@-]*){0,3})", query)
    if recipient_match:
        candidate = recipient_match.group(1).strip()
        candidate = re.sub(r"\s+\d.*$", "", candidate).strip()
        if candidate:
            fields["recipient"] = candidate
            fields["to"] = candidate
    quoted = re.search(r"['\"]([^'\"]+)['\"]", query)
    if quoted:
        fields["subject"] = quoted.group(1)
        fields["body"] = quoted.group(1)
        fields["content"] = quoted.group(1)
    channel_match = re.search(r"(?i)\b(?:channel|room)\s+([#@]?[A-Za-z0-9_.-]+)", query)
    if channel_match:
        fields["channel"] = channel_match.group(1)
    file_id_match = re.search(r"(?i)\b(?:file[_\s-]?id)\s*[:=]?\s*([A-Za-z0-9_.-]+)", query)
    if file_id_match:
        fields["file_id"] = file_id_match.group(1)
    url_match = re.search(r"https?://\S+", query)
    if url_match:
        fields["url"] = url_match.group(0).rstrip(".,)")
    if "participants" in lower or "attendees" in lower:
        participants = re.findall(r"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?\b", query)
        if participants:
            fields["participants"] = participants
    return fields


def summarize_task_flow_contract(contract: TaskFlowContract | None) -> dict[str, Any]:
    if contract is None:
        return {}
    return {
        "contract_version": contract.contract_version,
        "allowed_trajectory": list(contract.allowed_trajectory),
        "argument_contract": {
            sink: {
                "allowed_sources": list(binding.allowed_sources),
                "required_proofs": list(binding.required_proofs),
                "reason": binding.reason,
            }
            for sink, binding in contract.argument_contract.items()
        },
        "unresolved_bindings": [
            {
                "sink": binding.sink,
                "reason": binding.reason,
                "policy": binding.policy,
            }
            for binding in contract.unresolved_bindings
        ],
    }


def _generate_with_client(
    user_query: str,
    initial_function_trajectory: list[str],
    tool_schemas: list[dict[str, Any]],
    global_contract: IFCGlobalContract,
    client: Any,
    model: str | None,
) -> TaskFlowContract | None:
    global_subset = {
        name: ifc_to_jsonable(global_contract.tools[name])
        for name in initial_function_trajectory
        if name in global_contract.tools
    }
    user_prompt = json.dumps(
        {
            "original_user_task": user_query,
            "planned_function_trajectory": initial_function_trajectory,
            "tool_schemas": _relevant_tool_schemas(tool_schemas, initial_function_trajectory),
            "ifc_global_contract_subset": global_subset,
            "model": model or "",
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    response = client.llm_run(ARGUMENT_AUTHORITY_CONTRACT_PROMPT, user_prompt, name="ifc_task_flow_contract")
    if not response or "FAILED GENERATION" in response:
        return None
    try:
        repaired = repair_json(response)
        data = json.loads(repaired)
        return task_flow_contract_from_json(data, global_contract)
    except Exception:
        return None


def _relevant_tool_schemas(tool_schemas: list[dict[str, Any]], trajectory: list[str]) -> list[dict[str, Any]]:
    relevant = set(trajectory)
    return [schema for schema in tool_schemas if schema.get("name") in relevant]
