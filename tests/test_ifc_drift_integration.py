from __future__ import annotations

from types import SimpleNamespace

try:
    from DRIFTLLM import DRIFTLLM
except ModuleNotFoundError:  # pragma: no cover - depends on external optional runtime deps.
    DRIFTLLM = None


class _FakeParameters:
    def model_json_schema(self):
        return {"type": "object", "properties": {"amount": {"type": "number"}}}


class _FakeFunction:
    def __init__(self, name: str):
        self.name = name
        self.description = ""
        self.parameters = _FakeParameters()


class _FakeRuntime:
    def __init__(self):
        self.functions = {"send_money": _FakeFunction("send_money")}


class _FakeClient:
    def __init__(self, completion: str):
        self.completion = completion

    def agent_run(self, *args, **kwargs):
        return [self.completion]


class _FakeToolCall:
    def __init__(self, function: str, arguments: dict[str, object]):
        self.id = "call-1"
        self.function = function
        self.args = arguments


def test_ifc_query_uses_trajectory_then_argument_validation(monkeypatch) -> None:
    if DRIFTLLM is None:
        return
    args = SimpleNamespace(
        enable_ifc_drift=True,
        enable_pact_drift=False,
        build_constraints=False,
        dynamic_validation=False,
        injection_isolation=False,
        enable_argument_validation=False,
        ifc_global_contract_path="",
        ifc_task_contract_model="",
        ifc_debug=False,
        ifc_allow_action_replan=False,
        ifc_control_mode="strict_next_step",
    )
    client = _FakeClient('<function_call>[send_money(amount=1)]</function_call>')
    llm = DRIFTLLM(args, client)
    llm._ifc_drift_init_if_needed = lambda runtime: None
    llm.ifc_global_contract = SimpleNamespace(tools={}, tool_schema_hashes={})
    llm.ifc_provenance_state = SimpleNamespace()
    llm.task_flow_contract = SimpleNamespace(allowed_sources_for_sink=lambda sink: [], argument_contract={})
    llm.initial_function_trajectory = ["send_money"]
    llm.achieved_function_trajectory = []
    call_order: list[str] = []

    def _trajectory(*_args, **_kwargs):
        call_order.append("trajectory")
        return None, {"role": "assistant", "content": "ok", "tool_calls": [_FakeToolCall("send_money", {"amount": 1})]}

    def _argument(*_args, **_kwargs):
        call_order.append("argument")
        return None, {"role": "assistant", "content": "ok", "tool_calls": [_FakeToolCall("send_money", {"amount": 1})]}

    def _checklist(*_args, **_kwargs):
        call_order.append("checklist")
        return None, {"role": "assistant", "content": "ok", "tool_calls": []}

    llm.trajectory_constraint_validation = _trajectory
    llm.argument_authority_validation = _argument
    llm.checklist_constraint_validation = _checklist
    llm._parse_model_output = lambda message: {"role": "assistant", "content": message, "tool_calls": [_FakeToolCall("send_money", {"amount": 1})]}

    llm.query("pay invoice", _FakeRuntime(), messages=[])

    assert call_order == ["trajectory", "argument"]


def test_non_ifc_query_keeps_legacy_checklist_path(monkeypatch) -> None:
    if DRIFTLLM is None:
        return
    args = SimpleNamespace(
        enable_ifc_drift=False,
        enable_pact_drift=False,
        build_constraints=False,
        dynamic_validation=True,
        injection_isolation=False,
        enable_argument_validation=False,
        ifc_global_contract_path="",
        ifc_task_contract_model="",
        ifc_debug=False,
        ifc_allow_action_replan=False,
        ifc_control_mode="strict_next_step",
    )
    client = _FakeClient('<function_call>[send_money(amount=1)]</function_call>')
    llm = DRIFTLLM(args, client)
    llm.tool_permissions = {"send_money": "Read"}
    llm.initial_function_trajectory = ["send_money"]
    llm.achieved_function_trajectory = []
    llm.task_flow_contract = SimpleNamespace()
    call_order: list[str] = []

    def _trajectory(*_args, **_kwargs):
        call_order.append("trajectory")
        return None, {"role": "assistant", "content": "ok", "tool_calls": [_FakeToolCall("send_money", {"amount": 1})]}

    def _checklist(*_args, **_kwargs):
        call_order.append("checklist")
        return None, {"role": "assistant", "content": "ok", "tool_calls": []}

    llm.trajectory_constraint_validation = _trajectory
    llm.checklist_constraint_validation = _checklist
    llm._parse_model_output = lambda message: {"role": "assistant", "content": message, "tool_calls": [_FakeToolCall("send_money", {"amount": 1})]}
    llm._pact_drift_init_if_needed = lambda runtime: None
    llm._pact_record_latest_tool_output = lambda messages: None

    llm.query("pay invoice", _FakeRuntime(), messages=[])

    assert call_order == ["trajectory", "checklist"]
