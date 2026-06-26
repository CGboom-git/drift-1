from __future__ import annotations

import json
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
    del user_query
    flow_bindings: dict[str, list[FlowBinding]] = {}
    unresolved: list[UnresolvedBinding] = []
    if "send_money" in initial_function_trajectory and "read_file" in initial_function_trajectory:
        if "get_iban" in initial_function_trajectory:
            _add_binding(global_contract, flow_bindings, "send_money.recipient", "get_iban.output.iban", "DELEGATED", "USER_PRIVATE", "recipient derived from delegated invoice creditor")
        _add_binding(global_contract, flow_bindings, "send_money.amount", "read_file.output.invoice.amount", "DELEGATED", "SENSITIVE", "amount extracted from delegated invoice")
        _add_binding(global_contract, flow_bindings, "send_money.subject", "read_file.output.invoice.subject", "DELEGATED", "USER_PRIVATE", "subject extracted from delegated invoice")
        _add_binding(global_contract, flow_bindings, "send_money.date", "read_file.output.invoice.due_date", "DELEGATED", "SENSITIVE", "due date extracted from delegated invoice")
    for tool_name in initial_function_trajectory:
        tool = global_contract.tools.get(tool_name)
        if not tool or tool.tool_type != "ACTION":
            continue
        for argument_name, argument_contract in tool.args.items():
            sink = f"{tool_name}.{argument_name}"
            if sink in flow_bindings:
                continue
            unresolved.append(
                UnresolvedBinding(
                    sink=sink,
                    required_constraints=list(argument_contract.flow_constraints),
                    reason="No task-authorized provenance source was inferred by the deterministic fallback.",
                )
            )
            _add_binding(
                global_contract,
                flow_bindings,
                sink,
                f"user.explicit.{argument_name}",
                argument_contract.I_min,
                argument_contract.C_max,
                "argument may be used only if runtime provenance records an exact user-explicit value",
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


def summarize_task_flow_contract(contract: TaskFlowContract | None) -> dict[str, Any]:
    if contract is None:
        return {}
    return {
        "task_contract_version": contract.task_contract_version,
        "task_type": contract.task_type,
        "allowed_trajectory": contract.allowed_trajectory,
        "flow_binding_sinks": sorted(contract.flow_bindings),
        "unresolved_sinks": [binding.sink for binding in contract.unresolved_bindings],
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
            endorsements=list(argument_contract.endorsements),
            declassifications=[],
            reason=reason,
        )
    )


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
