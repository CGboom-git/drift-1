from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize PACT-DRIFT JSON result files.")
    parser.add_argument("--run_dir", required=True)
    args = parser.parse_args()
    totals = Counter()
    rejected_tools = Counter()
    rejected_arguments = Counter()
    for path in Path(args.run_dir).rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not data.get("pact_drift_enabled"):
            continue
        totals["cases"] += 1
        totals["utility"] += bool(data.get("utility"))
        totals["attack_success"] += bool(data.get("security"))
        summary = data.get("pact_drift_decision_summary") or {}
        for key in ("num_argument_checks", "num_rejected_tool_calls", "num_model_guess_arguments", "num_injected_origin_arguments"):
            totals[key] += summary.get(key, 0)
        for event in data.get("argument_validation_events", []):
            if event.get("decision") == "reject":
                rejected_tools[event.get("tool", "unknown")] += 1
                rejected_arguments[event.get("argument", "unknown")] += 1
    print(json.dumps({"totals": totals, "top_rejected_tools": rejected_tools.most_common(), "top_rejected_arguments": rejected_arguments.most_common()}, indent=2, default=int))


if __name__ == "__main__":
    main()
