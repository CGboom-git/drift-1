from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pact_drift.benchmark_adapters import AgentDojoAdapter, BenchmarkAdapter
from pact_drift.ifc_contract_generator import generate_ifc_global_contract, summarize_ifc_contract
from pact_drift.ifc_contract_schema import ifc_to_jsonable, save_ifc_global_contract


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an IFC-aligned PACT-DRIFT global contract draft.")
    parser.add_argument("--benchmark", default="agentdojo")
    parser.add_argument("--benchmark_version", default="v1.2")
    parser.add_argument("--suites", default="banking,slack,travel,workspace")
    parser.add_argument("--output", default="contracts/agentdojo_ifc_global_tool_contract_draft.json")
    parser.add_argument("--review_pack", default="contracts/agentdojo_ifc_global_tool_contract_review_pack.json")
    args = parser.parse_args()

    adapter = _adapter_for(args.benchmark)
    suites = [suite.strip() for suite in args.suites.split(",") if suite.strip()]
    tool_schemas = adapter.load_tool_schemas(benchmark_version=args.benchmark_version, suites=suites)
    contract = generate_ifc_global_contract(
        tool_schemas,
        benchmark=args.benchmark,
        adapter_metadata={
            "name": adapter.name,
            "version": adapter.version,
            "notes": "Benchmark-specific aliases are mapped to benchmark-agnostic IFC labels.",
        },
    )
    save_ifc_global_contract(contract, args.output)
    _save_review_pack(args.review_pack, args.output, args.benchmark, tool_schemas, contract, adapter)
    summary = summarize_ifc_contract(contract)
    print(f"Wrote {summary['tool_count']} IFC draft tool contracts to {args.output}")
    print(f"Wrote IFC review pack to {args.review_pack}")
    print(f"schema_hash={contract.schema_hash}")
    print(f"ACTION={summary['ACTION']}")
    print(f"READ_SENSITIVE={summary['READ_SENSITIVE']}")
    print(f"READ_LOW={summary['READ_LOW']}")
    print(f"argument_count={summary['argument_count']}")
    for role, count in summary["sink_roles"].items():
        print(f"sink_role.{role}={count}")
    for scope, count in summary["sink_scopes"].items():
        print(f"sink_scope.{scope}={count}")


def _adapter_for(benchmark: str) -> BenchmarkAdapter:
    if benchmark == "agentdojo":
        return AgentDojoAdapter()
    supported_later = "browsergym, webarena, osworld, tau_bench"
    raise ValueError(f"Unsupported benchmark '{benchmark}'. Current implementation supports agentdojo; reserved: {supported_later}.")


def _save_review_pack(
    path: str,
    draft_contract_path: str,
    benchmark: str,
    tool_schemas: list[dict],
    contract: object,
    adapter: BenchmarkAdapter,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    contract_json = ifc_to_jsonable(contract)
    review_pack = {
        "draft_contract_path": draft_contract_path,
        "benchmark": benchmark,
        "schema_hash": contract_json["schema_hash"],
        "tools": {
            schema["name"]: {
                "schema": schema,
                "draft_contract": contract_json["tools"][schema["name"]],
                "domain_aliases": adapter.infer_domain_aliases(schema),
            }
            for schema in tool_schemas
        },
    }
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(review_pack, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
