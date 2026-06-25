from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pact_drift.ifc_contract_schema import ifc_to_jsonable, load_ifc_global_contract


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate an IFC-aligned PACT-DRIFT global contract draft.")
    parser.add_argument("--contract_path", default="contracts/agentdojo_ifc_global_tool_contract_draft.json")
    args = parser.parse_args()
    contract = load_ifc_global_contract(args.contract_path)
    data = ifc_to_jsonable(contract)
    _validate_special_cases(data)
    print(f"Valid PACT-DRIFT IFC draft contract: {len(contract.tools)} tools, schema {contract.schema_hash}")


def _validate_special_cases(data: dict) -> None:
    tools = data["tools"]
    send_money = tools.get("send_money")
    if send_money is None:
        raise ValueError("IFC contract must define send_money.")
    if send_money["sink_scope"] != "financial":
        raise ValueError("send_money must use financial sink_scope.")
    expected_roles = {"recipient": "target", "amount": "control", "subject": "content", "date": "control"}
    for argument, role in expected_roles.items():
        if send_money["args"].get(argument, {}).get("sink_role") != role:
            raise ValueError(f"send_money.{argument} must have sink_role {role}.")
    _expect_arg_value(tools, "create_file", "content", "C_max", "USER_PRIVATE")
    _expect_arg_value(tools, "append_to_file", "content", "C_max", "USER_PRIVATE")
    _expect_arg_value(tools, "post_webpage", "content", "C_max", "PUBLIC")
    post_webpage = tools.get("post_webpage")
    if post_webpage and "no_private_to_public_sink" not in post_webpage["args"]["content"]["flow_constraints"]:
        raise ValueError("post_webpage.content must include no_private_to_public_sink.")
    share_file = tools.get("share_file")
    if share_file:
        file_arg = share_file["args"].get("file_id") or share_file["args"].get("file")
        if file_arg is None:
            raise ValueError("share_file must contain a file selector argument.")
        if "object_confidentiality_check" not in file_arg["flow_constraints"]:
            raise ValueError("share_file file argument must include object_confidentiality_check.")


def _expect_arg_value(tools: dict, tool_name: str, argument_name: str, field_name: str, expected: str) -> None:
    tool = tools.get(tool_name)
    if tool is None:
        return
    actual = tool["args"].get(argument_name, {}).get(field_name)
    if actual != expected:
        raise ValueError(f"{tool_name}.{argument_name}.{field_name} must be {expected}; got {actual}.")


if __name__ == "__main__":
    main()
