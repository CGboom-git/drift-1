from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pact_drift.contract_schema_l2 import FORBIDDEN_DISCHARGE_PROCEDURES, load_l2_global_contracts, l2_to_jsonable


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a PACT-DRIFT L2 draft tool contract.")
    parser.add_argument("--contract_path", default="contracts/agentdojo_global_tool_contracts_l2_draft.json")
    args = parser.parse_args()
    contracts = load_l2_global_contracts(args.contract_path)
    data = l2_to_jsonable(contracts)
    _validate_special_cases(data)
    _validate_no_forbidden_tokens(data)
    print(f"Valid PACT-DRIFT L2 draft contract: {len(contracts.tools)} tools, schema {contracts.schema_hash}")


def _validate_special_cases(data: dict) -> None:
    tools = data["tools"]
    send_money = tools.get("send_money")
    if send_money is None:
        raise ValueError("L2 contract must define send_money.")
    if send_money["tool_type"] != "ACTION":
        raise ValueError("send_money must be ACTION.")
    expected_roles = {"recipient": "target", "amount": "control", "subject": "content", "date": "control"}
    for argument, role in expected_roles.items():
        if send_money["args"].get(argument, {}).get("role") != role:
            raise ValueError(f"send_money.{argument} must have role {role}.")
    read_file = tools.get("read_file")
    if read_file is None:
        raise ValueError("L2 contract must define read_file.")
    if read_file["output"].get("raw_output_trust") != "EXTERNAL":
        raise ValueError("read_file raw output must remain EXTERNAL.")
    if read_file["output"].get("requires_structured_extraction") is not True:
        raise ValueError("read_file must require structured extraction.")
    get_iban = tools.get("get_iban")
    if get_iban is None:
        raise ValueError("L2 contract must define get_iban.")
    if get_iban["output"].get("propagate_input_origins") is not True:
        raise ValueError("get_iban output must propagate input origins.")


def _validate_no_forbidden_tokens(data: dict) -> None:
    text = json.dumps(data, sort_keys=True)
    for forbidden_role in ("financial_amount", "content_safety_critical"):
        if forbidden_role in text:
            raise ValueError(f"L2 contract must not contain legacy role {forbidden_role}.")
    for tool_name, tool in data["tools"].items():
        for argument_name, argument in tool["args"].items():
            for forbidden_discharge in FORBIDDEN_DISCHARGE_PROCEDURES:
                if forbidden_discharge in argument["D"]:
                    raise ValueError(
                        f"L2 contract must not contain forbidden discharge procedure "
                        f"{forbidden_discharge} in {tool_name}.{argument_name}."
                    )


if __name__ == "__main__":
    main()
