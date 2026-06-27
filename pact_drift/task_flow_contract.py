from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from pact_drift.ifc_contract_schema import IFCGlobalContract, IFCArgumentContract

TASK_CONTRACT_VERSION = "argument_authority_contract_v1"
TASK_CONTRACT_FORBIDDEN_KEYS = {"sink_role", "I_min", "C_max", "deny_marks"}
_ALLOWED_SOURCE_PREFIXES = ("user.explicit.",)
_ALLOWED_PROOFS = {"user_explicit", "structured_extraction", "trusted_tool_derivation"}


@dataclass
class ArgumentAuthorityBinding:
    allowed_sources: list[str] = field(default_factory=list)
    required_proofs: list[str] = field(default_factory=list)
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return task_flow_contract_to_jsonable(self)


@dataclass
class UnresolvedArgumentBinding:
    sink: str
    reason: str
    policy: str = "safe_refusal"


@dataclass
class TaskFlowContract:
    contract_version: str
    allowed_trajectory: list[str]
    argument_contract: dict[str, ArgumentAuthorityBinding]
    unresolved_bindings: list[UnresolvedArgumentBinding]

    def to_json(self) -> dict[str, Any]:
        return task_flow_contract_to_jsonable(self)

    def allowed_sources_for_sink(self, sink: str) -> list[str]:
        binding = self.argument_contract.get(sink)
        return list(binding.allowed_sources) if binding else []

    def allowed_paths_for_sink(self, sink: str) -> list[str]:
        return self.allowed_sources_for_sink(sink)

    def bindings_for_sink(self, sink: str) -> list[ArgumentAuthorityBinding]:
        binding = self.argument_contract.get(sink)
        return [binding] if binding else []


def task_flow_contract_to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        data = asdict(obj)
        return {key: task_flow_contract_to_jsonable(value) for key, value in data.items()}
    if isinstance(obj, dict):
        return {key: task_flow_contract_to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [task_flow_contract_to_jsonable(value) for value in obj]
    if isinstance(obj, set):
        return sorted(task_flow_contract_to_jsonable(value) for value in obj)
    return obj


def task_flow_contract_from_json(data: dict[str, Any], global_contract: IFCGlobalContract) -> TaskFlowContract:
    validate_task_flow_contract_schema(data, global_contract)
    return TaskFlowContract(
        contract_version=data["contract_version"],
        allowed_trajectory=[str(item) for item in data.get("allowed_trajectory", [])],
        argument_contract={
            sink: ArgumentAuthorityBinding(
                allowed_sources=[str(source) for source in binding.get("allowed_sources", [])],
                required_proofs=[str(proof) for proof in binding.get("required_proofs", [])],
                reason=str(binding.get("reason", "")),
            )
            for sink, binding in data.get("argument_contract", {}).items()
        },
        unresolved_bindings=[
            UnresolvedArgumentBinding(
                sink=str(binding["sink"]),
                reason=str(binding.get("reason", "")),
                policy=str(binding.get("policy", "safe_refusal")),
            )
            for binding in data.get("unresolved_bindings", [])
        ],
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
    for field_name in ("contract_version", "allowed_trajectory", "argument_contract", "unresolved_bindings"):
        if field_name not in data:
            raise ValueError(f"IFC task argument contract is missing required field '{field_name}'.")
    if data["contract_version"] != TASK_CONTRACT_VERSION:
        raise ValueError(f"Unsupported IFC task argument contract version '{data['contract_version']}'.")
    if not isinstance(data["allowed_trajectory"], list):
        raise ValueError("IFC task argument contract allowed_trajectory must be a list.")
    if not isinstance(data["argument_contract"], dict):
        raise ValueError("IFC task argument contract argument_contract must be an object.")
    if not isinstance(data["unresolved_bindings"], list):
        raise ValueError("IFC task argument contract unresolved_bindings must be a list.")

    trajectory = {str(item) for item in data["allowed_trajectory"]}
    for sink, binding in data["argument_contract"].items():
        _validate_argument_binding(sink, binding, global_contract, trajectory)
    for unresolved in data["unresolved_bindings"]:
        _validate_unresolved_binding(unresolved, global_contract, trajectory)


def _validate_argument_binding(
    sink: str,
    binding: dict[str, Any],
    global_contract: IFCGlobalContract,
    trajectory: set[str],
) -> None:
    for field_name in ("allowed_sources", "required_proofs", "reason"):
        if field_name not in binding:
            raise ValueError(f"IFC task argument binding '{sink}' is missing '{field_name}'.")
    global_arg = _global_argument(global_contract, sink)
    tool_name, _ = sink.split(".", 1)
    if tool_name not in trajectory:
        raise ValueError(f"IFC task argument binding '{sink}' references a tool outside the allowed trajectory.")
    if not isinstance(binding["allowed_sources"], list):
        raise ValueError(f"IFC task argument binding '{sink}' allowed_sources must be a list.")
    if not isinstance(binding["required_proofs"], list):
        raise ValueError(f"IFC task argument binding '{sink}' required_proofs must be a list.")
    _require_proofs_subset(sink, binding["required_proofs"], global_contract)
    for source_path in binding["allowed_sources"]:
        _validate_source_path(sink, str(source_path), trajectory)
    if any(key in binding for key in TASK_CONTRACT_FORBIDDEN_KEYS):
        raise ValueError(f"IFC task argument binding '{sink}' must not contain legacy global contract fields.")
    if not isinstance(binding["reason"], str):
        raise ValueError(f"IFC task argument binding '{sink}' reason must be a string.")
    _global_argument(global_contract, sink)


def _validate_unresolved_binding(unresolved: dict[str, Any], global_contract: IFCGlobalContract, trajectory: set[str]) -> None:
    sink = unresolved.get("sink")
    if not isinstance(sink, str):
        raise ValueError("IFC unresolved argument binding must include a sink string.")
    tool_name, _ = sink.split(".", 1)
    if tool_name not in trajectory:
        raise ValueError(f"IFC unresolved argument binding '{sink}' references a tool outside the allowed trajectory.")
    _global_argument(global_contract, sink)
    if not isinstance(unresolved.get("reason", ""), str):
        raise ValueError(f"IFC unresolved argument binding '{sink}' reason must be a string.")
    if unresolved.get("policy", "safe_refusal") != "safe_refusal":
        raise ValueError(f"IFC unresolved argument binding '{sink}' must use safe_refusal policy.")


def _validate_source_path(sink: str, source_path: str, trajectory: set[str]) -> None:
    if source_path.startswith("user.explicit."):
        return
    if " -> " in source_path:
        left, right = [part.strip() for part in source_path.split("->", 1)]
        _validate_single_source_path(sink, left, trajectory)
        _validate_single_source_path(sink, right, trajectory)
        return
    _validate_single_source_path(sink, source_path, trajectory)


def _validate_single_source_path(sink: str, source_path: str, trajectory: set[str]) -> None:
    if not source_path:
        raise ValueError(f"IFC task argument binding '{sink}' has an empty allowed source path.")
    if source_path.startswith("user.explicit."):
        return
    try:
        tool_name, remainder = source_path.split(".output.", 1)
    except ValueError as exc:
        raise ValueError(f"IFC task argument binding '{sink}' has invalid source path '{source_path}'.") from exc
    if tool_name not in trajectory:
        raise ValueError(f"IFC task argument binding '{sink}' references source tool '{tool_name}' outside the trajectory.")
    if not remainder:
        raise ValueError(f"IFC task argument binding '{sink}' has incomplete source path '{source_path}'.")


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


def _require_proofs_subset(sink: str, proofs: list[str], global_contract: IFCGlobalContract) -> None:
    allowed = set(global_contract.endorsement_types)
    extra = set(proofs) - allowed
    if extra:
        raise ValueError(f"IFC task argument binding '{sink}' has unsupported required proofs: {sorted(extra)}.")


def _reject_global_policy_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in TASK_CONTRACT_FORBIDDEN_KEYS:
                raise ValueError(f"IFC task argument contract must not contain global policy field '{key}'.")
            _reject_global_policy_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_global_policy_fields(nested)
