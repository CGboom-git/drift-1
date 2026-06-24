from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agentdojo.task_suite.load_suites import get_suite

from pact_drift.contract_generator import generate_global_tool_contracts
from pact_drift.contracts import save_global_contracts
from pact_drift.schema_utils import collect_tool_schemas_from_functions


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate one frozen PACT-DRIFT contract from complete tool schemas.")
    parser.add_argument("--benchmark_version", default="v1.2")
    parser.add_argument("--suites", default="banking,slack,travel,workspace")
    parser.add_argument("--model", default="offline")
    parser.add_argument("--output", default="contracts/agentdojo_global_tool_contracts.json")
    args = parser.parse_args()

    schemas_by_name = {}
    for suite_name in args.suites.split(","):
        suite = get_suite(args.benchmark_version, suite_name)
        schemas_by_name.update({schema["name"]: schema for schema in collect_tool_schemas_from_functions(suite.tools)})
    contracts = generate_global_tool_contracts(list(sorted(schemas_by_name.values(), key=lambda schema: schema["name"])), model_name=args.model)
    save_global_contracts(contracts, args.output)
    print(f"Wrote {len(contracts.tools)} frozen tool contracts to {args.output}")


if __name__ == "__main__":
    main()
