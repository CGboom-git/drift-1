from __future__ import annotations

from pact_drift.benchmark_adapters.agentdojo import AgentDojoAdapter
from pact_drift.ifc_contract_generator import generate_ifc_global_contract
from pact_drift.ifc_contract_schema import ifc_to_jsonable


def test_agentdojo_adapter_loads_deduplicated_tool_schemas() -> None:
    adapter = AgentDojoAdapter()
    schemas = adapter.load_tool_schemas(benchmark_version="v1.2", suites=["banking"])
    assert schemas
    assert len({schema["name"] for schema in schemas}) == len(schemas)
    for schema in schemas:
        assert "name" in schema
        assert "description" in schema
        assert "parameters" in schema


def test_agentdojo_aliases_do_not_enter_core_contract_enums() -> None:
    adapter = AgentDojoAdapter()
    aliases = adapter.infer_domain_aliases({"name": "get_most_recent_transactions"})
    assert aliases["unrequested_transaction_history"] == "unauthorized_tool_output"
    schemas = [{"name": "get_most_recent_transactions", "description": "", "parameters": {"type": "object", "properties": {"n": {"type": "integer"}}}}]
    contract = ifc_to_jsonable(generate_ifc_global_contract(schemas, "agentdojo", {"name": adapter.name, "version": adapter.version}))
    assert "unrequested_transaction_history" not in str(contract["deny_mark_types"])


def test_review_pack_shape_contains_schema_and_draft_contract() -> None:
    schema = {"name": "send_money", "description": "", "parameters": {"type": "object", "properties": {"recipient": {"type": "string"}}}}
    adapter = AgentDojoAdapter()
    contract = ifc_to_jsonable(generate_ifc_global_contract([schema], "agentdojo", {"name": adapter.name, "version": adapter.version}))
    review_entry = {
        "schema": schema,
        "draft_contract": contract["tools"]["send_money"],
        "domain_aliases": adapter.infer_domain_aliases(schema),
    }
    assert "schema" in review_entry
    assert "draft_contract" in review_entry
    assert "domain_aliases" in review_entry
