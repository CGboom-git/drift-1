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
    FlowBinding,
    TaskFlowContract,
    UnresolvedBinding,
    task_flow_contract_from_json,
)
from prompts import IFC_TASK_FLOW_CONTRACT_PROMPT


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
    return deterministic_task_flow_contract(user_query, initial_function_trajectory, global_contract)


def deterministic_task_flow_contract(
    user_query: str,
    initial_function_trajectory: list[str],
    global_contract: IFCGlobalContract,
) -> TaskFlowContract:
    explicit_fields = extract_explicit_user_fields(user_query)
    flow_bindings: dict[str, list[FlowBinding]] = {}
    unresolved: list[UnresolvedBinding] = []
    _try_banking_invoice_fallback(
        user_query,
        initial_function_trajectory,
        global_contract,
        flow_bindings,
        unresolved,
    )
    for tool_name in initial_function_trajectory:
        tool = global_contract.tools.get(tool_name)
        if not tool or tool.tool_type != "ACTION":
            continue
        for argument_name, argument_contract in tool.args.items():
            sink = f"{tool_name}.{argument_name}"
            if sink in flow_bindings:
                continue
            explicit_value = explicit_fields.get(argument_name)
            if explicit_value is not None:
                _add_binding(
                    global_contract,
                    flow_bindings,
                    sink,
                    f"user.explicit.{argument_name}",
                    "USER",
                    argument_contract.C_max,
                    "argument value was explicitly present in the original user query",
                    endorsements=_explicit_endorsements(argument_contract.endorsements),
                )
            else:
                unresolved.append(
                    UnresolvedBinding(
                        sink=sink,
                        required_constraints=list(argument_contract.flow_constraints),
                        reason="No task-authorized provenance source was inferred by the deterministic fallback.",
                    )
                )
    contract = TaskFlowContract(
        task_contract_version=TASK_CONTRACT_VERSION,
        task_type=_task_type(initial_function_trajectory),
        allowed_trajectory=list(initial_function_trajectory),
        opportunistic_read_policy={
            "READ_LOW": "allow_and_track",
            "READ_SENSITIVE": "allow_and_quarantine_unless_task_delegated",
            "output_can_flow_to_action_by_default": False,
        },
        source_delegations=_source_delegations(flow_bindings),
        flow_bindings=flow_bindings,
        unresolved_bindings=unresolved,
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
    compact_bindings = {}
    for sink, bindings in contract.flow_bindings.items():
        compact_bindings[sink] = [
            {
                "source_path": binding.source_path,
                "I_after": binding.I_after,
                "C_label": binding.C_label,
                "satisfies": list(binding.satisfies),
                "reason": binding.reason,
            }
            for binding in bindings
        ]
    return {
        "task_contract_version": contract.task_contract_version,
        "task_type": contract.task_type,
        "allowed_trajectory": contract.allowed_trajectory,
        "flow_bindings": compact_bindings,
        "unresolved_bindings": [
            {
                "sink": item.sink,
                "required_constraints": list(item.required_constraints),
                "reason": item.reason,
                "policy": item.policy,
            }
            for item in contract.unresolved_bindings
        ],
        "opportunistic_read_policy": contract.opportunistic_read_policy,
    }


def _generate_with_client(
    user_query: str,
    initial_function_trajectory: list[str],
    tool_schemas: list[dict[str, Any]],
    global_contract: IFCGlobalContract,
    client: Any,
    model: str | None,
) -> TaskFlowContract | None:
    relevant_tools = _relevant_tool_schemas(tool_schemas, initial_function_trajectory)
    global_subset = {
        name: ifc_to_jsonable(global_contract.tools[name])
        for name in initial_function_trajectory
        if name in global_contract.tools
    }
    user_prompt = json.dumps(
        {
            "original_user_task": user_query,
            "planned_function_trajectory": initial_function_trajectory,
            "tool_schemas": relevant_tools,
            "ifc_global_contract_subset": global_subset,
            "model": model or "",
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    response = client.llm_run(IFC_TASK_FLOW_CONTRACT_PROMPT, user_prompt, name="ifc_task_flow_contract")
    if not response or "FAILED GENERATION" in response:
        return None
    try:
        repaired = repair_json(response)
        data = json.loads(repaired)
        return task_flow_contract_from_json(data, global_contract)
    except Exception:
        return None


def _add_binding(
    global_contract: IFCGlobalContract,
    flow_bindings: dict[str, list[FlowBinding]],
    sink: str,
    source_path: str,
    i_after: str,
    c_label: str,
    reason: str,
    endorsements: list[str] | None = None,
) -> None:
    tool_name, argument_name = sink.split(".", 1)
    argument_contract = global_contract.tools[tool_name].args[argument_name]
    flow_bindings.setdefault(sink, []).append(
        FlowBinding(
            source_path=source_path,
            sink=sink,
            I_after=i_after,
            C_label=c_label,
            satisfies=list(argument_contract.flow_constraints),
            endorsements=list(endorsements) if endorsements is not None else list(argument_contract.endorsements),
            declassifications=[],
            reason=reason,
        )
    )


def _add_binding_if_allowed(
    global_contract: IFCGlobalContract,
    flow_bindings: dict[str, list[FlowBinding]],
    sink: str,
    source_path: str,
    i_after: str,
    c_label: str,
    reason: str,
    requested_endorsements: list[str],
) -> bool:
    try:
        tool_name, argument_name = sink.split(".", 1)
        argument_contract = global_contract.tools[tool_name].args[argument_name]
    except (KeyError, ValueError):
        return False
    endorsements = [item for item in requested_endorsements if item in argument_contract.endorsements]
    flow_bindings.setdefault(sink, []).append(
        FlowBinding(
            source_path=source_path,
            sink=sink,
            I_after=i_after,
            C_label=c_label,
            satisfies=list(argument_contract.flow_constraints),
            endorsements=endorsements,
            declassifications=[],
            reason=reason,
        )
    )
    return True


def _try_banking_invoice_fallback(
    user_query: str,
    initial_function_trajectory: list[str],
    global_contract: IFCGlobalContract,
    flow_bindings: dict[str, list[FlowBinding]],
    unresolved: list[UnresolvedBinding],
) -> bool:
    """Add deterministic bindings for canonical invoice payment tasks."""
    if not _looks_like_invoice_payment_task(user_query, initial_function_trajectory):
        return False
    send_money = global_contract.tools.get("send_money")
    if send_money is None or send_money.tool_type != "ACTION":
        return False

    applied = False
    common_endorsements = [
        "task_delegation",
        "structured_extraction",
        "schema_validated_parse",
        "exact_match_to_authorized_source",
    ]
    if "get_iban" in initial_function_trajectory and "recipient" in send_money.args:
        applied = _add_binding_if_allowed(
            global_contract,
            flow_bindings,
            "send_money.recipient",
            "get_iban.output.iban",
            "DELEGATED",
            "USER_PRIVATE",
            "recipient is derived from the task-delegated invoice creditor through get_iban",
            [*common_endorsements, "trusted_tool_derivation"],
        ) or applied
    elif "recipient" in send_money.args:
        _add_unresolved_once(
            unresolved,
            "send_money.recipient",
            list(send_money.args["recipient"].flow_constraints),
            "Canonical invoice payment fallback requires get_iban before authorizing send_money.recipient.",
        )

    invoice_bindings = {
        "amount": ("read_file.output.invoice.amount", "SENSITIVE", "amount is extracted from the task-delegated invoice"),
        "subject": ("read_file.output.invoice.subject", "USER_PRIVATE", "subject is extracted from the task-delegated invoice"),
        "date": ("read_file.output.invoice.due_date", "SENSITIVE", "due date is extracted from the task-delegated invoice"),
    }
    for argument_name, (source_path, c_label, reason) in invoice_bindings.items():
        if argument_name not in send_money.args:
            continue
        applied = _add_binding_if_allowed(
            global_contract,
            flow_bindings,
            f"send_money.{argument_name}",
            source_path,
            "DELEGATED",
            c_label,
            reason,
            common_endorsements,
        ) or applied
    return applied


def _looks_like_invoice_payment_task(user_query: str, trajectory: list[str]) -> bool:
    lower = user_query.lower()
    has_payment = any(word in lower for word in ["pay", "payment", "transfer", "send money"])
    has_invoice = any(word in lower for word in ["invoice", "bill", "receipt"])
    has_file = any(token in lower for token in [".txt", ".pdf", "file", "document", "invoice", "bill"])
    return has_payment and has_invoice and has_file and "read_file" in trajectory and "send_money" in trajectory


def _add_unresolved_once(
    unresolved: list[UnresolvedBinding],
    sink: str,
    required_constraints: list[str],
    reason: str,
) -> None:
    if sink in {item.sink for item in unresolved}:
        return
    unresolved.append(
        UnresolvedBinding(
            sink=sink,
            required_constraints=required_constraints,
            reason=reason,
        )
    )


def _explicit_endorsements(global_endorsements: list[str]) -> list[str]:
    evidence = ["user_explicit", "exact_match_to_authorized_source"]
    return [endorsement for endorsement in evidence if endorsement in global_endorsements]


def _source_delegations(flow_bindings: dict[str, list[FlowBinding]]) -> list[dict[str, Any]]:
    delegated_fields = {}
    for bindings in flow_bindings.values():
        for binding in bindings:
            if binding.source_path.startswith("read_file.output.invoice."):
                field_name = binding.source_path.removeprefix("read_file.output.invoice.")
                delegated_fields[f"invoice.{field_name}"] = {
                    "source_path": binding.source_path,
                    "I_after": binding.I_after,
                    "C_label": binding.C_label,
                    "satisfies": binding.satisfies,
                    "endorsements": binding.endorsements,
                    "declassifications": binding.declassifications,
                }
    if not delegated_fields:
        return []
    return [
        {
            "source": "read_file(invoice)",
            "source_kind": "external_document",
            "authorized_by_task": True,
            "instruction_text_authorized": False,
            "default_I_label": "EXTERNAL",
            "default_C_label": "USER_PRIVATE",
            "extractable_fields": delegated_fields,
        }
    ]


def _relevant_tool_schemas(tool_schemas: list[dict[str, Any]], trajectory: list[str]) -> list[dict[str, Any]]:
    names = set(trajectory)
    return [schema for schema in tool_schemas if schema.get("name") in names]


def _task_type(initial_function_trajectory: list[str]) -> str:
    if "send_money" in initial_function_trajectory:
        return "banking_payment"
    if any(name.startswith("send_") for name in initial_function_trajectory):
        return "messaging_action"
    if any(name in {"post_webpage", "share_file"} for name in initial_function_trajectory):
        return "external_public_output"
    return "general_tool_task"
