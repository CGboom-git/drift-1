from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pact_drift.contracts import load_global_contracts


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a frozen PACT-DRIFT tool contract.")
    parser.add_argument("--contract_path", default="contracts/agentdojo_global_tool_contracts.json")
    args = parser.parse_args()
    contracts = load_global_contracts(args.contract_path)
    send_money = contracts.tools.get("send_money")
    if send_money is None or send_money.tool_type != "ACTION":
        raise ValueError("Contract must define send_money as ACTION.")
    for argument in ("recipient", "amount", "subject", "date"):
        if argument not in send_money.arguments:
            raise ValueError(f"send_money contract is missing '{argument}'.")
    for argument in ("recipient", "amount", "date"):
        if send_money.arguments[argument].allow_model_generated:
            raise ValueError(f"send_money.{argument} must not allow model-generated values.")
    print(f"Valid PACT-DRIFT contract: {len(contracts.tools)} tools, schema {contracts.schema_hash}")


if __name__ == "__main__":
    main()
