from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agentdojo.task_suite.load_suites import get_suite

from pact_drift.contract_generator_l2 import generate_global_tool_contracts_l2, summarize_l2_contracts
from pact_drift.contract_schema_l2 import l2_to_jsonable, save_l2_global_contracts
from pact_drift.schema_utils import collect_tool_schemas_from_functions


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a PACT-DRIFT L2 draft contract from complete tool schemas.")
    parser.add_argument("--benchmark_version", default="v1.2")
    parser.add_argument("--suites", default="banking,slack,travel,workspace")
    parser.add_argument("--output", default="contracts/agentdojo_global_tool_contracts_l2_draft.json")
    parser.add_argument("--review_pack", default="contracts/agentdojo_global_tool_contracts_l2_review_pack.json")
    args = parser.parse_args()

    schemas_by_name = _collect_schemas(args.benchmark_version, args.suites)
    ordered_schemas = list(sorted(schemas_by_name.values(), key=lambda schema: schema["name"]))
    contracts = generate_global_tool_contracts_l2(ordered_schemas)
    save_l2_global_contracts(contracts, args.output)
    _save_review_pack(args.review_pack, args.output, contracts.schema_hash, ordered_schemas, contracts)
    summary = summarize_l2_contracts(contracts)
    print(f"Wrote {summary['tool_count']} L2 draft tool contracts to {args.output}")
    print(f"Wrote L2 review pack to {args.review_pack}")
    print(f"schema_hash={contracts.schema_hash}")
    print(f"ACTION={summary['ACTION']}")
    print(f"READ_SENSITIVE={summary['READ_SENSITIVE']}")
    print(f"READ_LOW={summary['READ_LOW']}")
    print(f"argument_count={summary['argument_count']}")
    for role, count in summary["roles"].items():
        print(f"role.{role}={count}")


def _collect_schemas(benchmark_version: str, suites: str) -> dict[str, dict]:
    schemas_by_name = {}
    for suite_name in [suite.strip() for suite in suites.split(",") if suite.strip()]:
        suite = get_suite(benchmark_version, suite_name)
        for schema in collect_tool_schemas_from_functions(suite.tools):
            schemas_by_name[schema["name"]] = schema
    return schemas_by_name


def _save_review_pack(
    path: str,
    draft_contract_path: str,
    schema_hash: str,
    tool_schemas: list[dict],
    contracts: object,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    contract_json = l2_to_jsonable(contracts)
    review_pack = {
        "draft_contract_path": draft_contract_path,
        "schema_hash": schema_hash,
        "tools": {
            schema["name"]: {"schema": schema, "draft_contract": contract_json["tools"][schema["name"]]}
            for schema in tool_schemas
        },
    }
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(review_pack, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
