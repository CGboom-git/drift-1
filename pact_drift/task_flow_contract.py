from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from pact_drift.ifc_contract_schema import (
    CONFIDENTIALITY_LATTICE,
    INTEGRITY_LATTICE,
    IFCArgumentContract,
    IFCGlobalContract,
)

TASK_CONTRACT_VERSION = "pact_drift_ifc_task_v1"
TASK_CONTRACT_FORBIDDEN_KEYS = {"sink_role", "I_min", "C_max", "deny_marks"}


@dataclass
class FlowBinding:
    source_path: str
    sink: str
    I_after: str
    C_label: str
    satisfies: list[str] = field(default_factory=list)
    endorsements: list[str] = field(default_factory=list)
    declassifications: list[str] = field(default_factory=list)
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return task_flow_contract_to_jsonable(self)


@dataclass
class UnresolvedBinding:
    sink: str
    required_constraints: list[str]
    reason: str
    policy: str = "safe_refusal"


@dataclass
class TaskFlowContract:
    task_contract_version: str
    task_type: str
    allowed_trajectory: list[str]
    opportunistic_read_policy: dict[str, Any]
    source_delegations: list[dict[str, Any]]
    flow_bindings: dict[str, list[FlowBinding]]
    unresolved_bindings: list[UnresolvedBinding]
    missing_required_field: str = "safe_refusal"

    def to_json(self) -> dict[str, Any]:
        return task_flow_contract_to_jsonable(self)

    def allowed_paths_for_sink(self, sink: str) -> list[str]:
        return [binding.source_path for binding in self.flow_bindings.get(sink, [])]

    def bindings_for_sink(self, sink: str) -> list[FlowBinding]:
        return self.flow_bindings.get(sink, [])


def task_flow_contract_to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return {key: task_flow_contract_to_jsonable(value) for key, value in asdict(obj).items()}
    if isinstance(obj, dict):
        return {key: task_flow_contract_to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [task_flow_contract_to_jsonable(value) for value in obj]
    return obj


def task_flow_contract_from_json(data: dict[str, Any], global_contract: IFCGlobalContract) -> TaskFlowContract:
    validate_task_flow_contract_schema(data, global_contract)
    return TaskFlowContract(
        task_contract_version=data["task_contract_version"],
        task_type=data["task_type"],
        allowed_trajectory=list(data["allowed_trajectory"]),
        opportunistic_read_policy=dict(data["opportunistic_read_policy"]),
        source_delegations=list(data.get("source_delegations", [])),
        flow_bindings={
            sink: [FlowBinding(**binding) for binding in bindings]
            for sink, bindings in data.get("flow_bindings", {}).items()
        },
        unresolved_bindings=[
            UnresolvedBinding(**binding) for binding in data.get("unresolved_bindings", [])
        ],
        missing_required_field=data.get("missing_required_field", "safe_refusal"),
    )


def load_task_flow_contract(path: str, global_contract: IFCGlobalContract) -> TaskFlowContract:
    with Path(path).open("r", encoding="utf-8") as handle:
        return task_flow_contract_from_json(json.load(handle), global_contract)


def save_task_flow_contract(contract: TaskFlowContract, path: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(contract.to_json(), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def validate_task_flow_contract_schema(data: dict[str, Any], global_contract: IFCGlobalContract) -> None:
    _reject_global_policy_fields(data)
    for field_name in (
        "task_contract_version",
        "task_type",
        "allowed_trajectory",
        "opportunistic_read_policy",
        "source_delegations",
        "flow_bindings",
        "unresolved_bindings",
        "missing_required_field",
    ):
        if field_name not in data:
            raise ValueError(f"IFC task flow contract is missing required field '{field_name}'.")
    if data["task_contract_version"] != TASK_CONTRACT_VERSION:
        raise ValueError(f"Unsupported IFC task flow contract version '{data['task_contract_version']}'.")
    if not isinstance(data["allowed_trajectory"], list):
        raise ValueError("IFC task flow contract allowed_trajectory must be a list.")
    if not isinstance(data["flow_bindings"], dict):
        raise ValueError("IFC task flow contract flow_bindings must be an object.")
    for sink, bindings in data["flow_bindings"].items():
        global_arg = _global_argument(global_contract, sink)
        if not isinstance(bindings, list):
            raise ValueError(f"IFC task flow binding '{sink}' must be a list.")
        for binding in bindings:
            _validate_flow_binding(sink, binding, global_arg)
    for unresolved in data.get("unresolved_bindings", []):
        sink = unresolved.get("sink")
        if not isinstance(sink, str):
            raise ValueError("IFC unresolved binding must include a sink string.")
        _global_argument(global_contract, sink)
        required = unresolved.get("required_constraints", [])
        if not set(required).issubset(set(_global_argument(global_contract, sink).flow_constraints)):
            raise ValueError(f"IFC unresolved binding '{sink}' references constraints outside the global contract.")


def _validate_flow_binding(sink: str, binding: dict[str, Any], global_arg: IFCArgumentContract) -> None:
    for field_name in (
        "source_path",
        "sink",
        "I_after",
        "C_label",
        "satisfies",
        "endorsements",
        "declassifications",
        "reason",
    ):
        if field_name not in binding:
            raise ValueError(f"IFC flow binding '{sink}' is missing '{field_name}'.")
    if binding["sink"] != sink:
        raise ValueError(f"IFC flow binding key '{sink}' does not match binding sink '{binding['sink']}'.")
    if binding["I_after"] not in INTEGRITY_LATTICE:
        raise ValueError(f"IFC flow binding '{sink}' has invalid I_after '{binding['I_after']}'.")
    if binding["C_label"] not in CONFIDENTIALITY_LATTICE:
        raise ValueError(f"IFC flow binding '{sink}' has invalid C_label '{binding['C_label']}'.")
    _require_subset(sink, "satisfies", binding["satisfies"], global_arg.flow_constraints)
    _require_subset(sink, "endorsements", binding["endorsements"], global_arg.endorsements)
    _require_subset(sink, "declassifications", binding["declassifications"], global_arg.declassifications)


def _global_argument(global_contract: IFCGlobalContract, sink: str) -> IFCArgumentContract:
    try:
        tool_name, argument_name = sink.split(".", 1)
    except ValueError as exc:
        raise ValueError(f"IFC sink '{sink}' must use tool.argument format.") from exc
    tool_contract = global_contract.tools.get(tool_name)
    if tool_contract is None:
        raise ValueError(f"IFC sink '{sink}' references unknown tool '{tool_name}'.")
    argument_contract = tool_contract.args.get(argument_name)
    if argument_contract is None:
        raise ValueError(f"IFC sink '{sink}' references unknown argument '{argument_name}'.")
    return argument_contract


def _require_subset(sink: str, field_name: str, values: Any, allowed: list[str]) -> None:
    if not isinstance(values, list):
        raise ValueError(f"IFC flow binding '{sink}' field '{field_name}' must be a list.")
    extra = set(values) - set(allowed)
    if extra:
        raise ValueError(f"IFC flow binding '{sink}' has invalid {field_name}: {sorted(extra)}.")


def _reject_global_policy_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in TASK_CONTRACT_FORBIDDEN_KEYS:
                raise ValueError(f"IFC task flow contract must not contain global policy field '{key}'.")
            _reject_global_policy_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_global_policy_fields(nested)
