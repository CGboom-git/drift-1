from __future__ import annotations

from pathlib import Path

from pact_drift.ifc_contract_schema import IFCGlobalContract, load_ifc_global_contract

DEFAULT_IFC_GLOBAL_CONTRACT_CANDIDATES = (
    "contract/agentdojo_ifc_global_tool_contract_semantic_review_gpt55.json",
    "contracts/agentdojo_ifc_global_tool_contract_semantic_review_gpt55.json",
)


def resolve_ifc_global_contract_path(configured_path: str | None = None) -> str:
    candidates = [configured_path] if configured_path else []
    candidates.extend(DEFAULT_IFC_GLOBAL_CONTRACT_CANDIDATES)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise FileNotFoundError(
        "Could not find an IFC global contract. Tried: "
        + ", ".join(candidate for candidate in candidates if candidate)
    )


def load_default_ifc_global_contract(configured_path: str | None = None) -> tuple[IFCGlobalContract, str]:
    path = resolve_ifc_global_contract_path(configured_path)
    return load_ifc_global_contract(path), path
