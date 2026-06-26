from __future__ import annotations

import sys
import ast
from pathlib import Path

from utils import get_args


def test_ifc_cli_args_exist_and_default_to_disabled() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["prog"]
        args = get_args()
    finally:
        sys.argv = original_argv
    assert args.enable_ifc_drift is False
    assert args.ifc_global_contract_path is None
    assert args.ifc_task_contract_model is None
    assert args.ifc_debug is False
    assert args.ifc_allow_action_replan is False
    assert args.ifc_control_mode == "strict_next_step"
    assert args.ifc_disable_legacy_checklist is False


def test_ifc_cli_enables_legacy_checklist_disable() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["prog", "--enable_ifc_drift"]
        args = get_args()
    finally:
        sys.argv = original_argv
    assert args.enable_ifc_drift is True
    assert args.ifc_disable_legacy_checklist is True


def test_openai_and_openrouter_agent_run_accept_ifc_kwargs() -> None:
    classes = _client_classes()
    for class_name in ("OpenAIModel", "OpenRouterModel"):
        args = _method_args(classes[class_name], "agent_run")
        assert "task_flow_contract_summary" in args
        assert "use_ifc_execution_guidelines" in args


def test_google_agent_run_accepts_ifc_kwargs_via_kwargs() -> None:
    classes = _client_classes()
    method = _method(classes["GoogleModel"], "agent_run")
    assert method.args.kwarg is not None


def _client_classes() -> dict[str, ast.ClassDef]:
    tree = ast.parse(Path("client.py").read_text(encoding="utf-8"))
    return {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}


def _method(class_node: ast.ClassDef, method_name: str) -> ast.FunctionDef:
    for node in class_node.body:
        if isinstance(node, ast.FunctionDef) and node.name == method_name:
            return node
    raise AssertionError(f"{class_node.name}.{method_name} not found")


def _method_args(class_node: ast.ClassDef, method_name: str) -> set[str]:
    return {arg.arg for arg in _method(class_node, method_name).args.args}
