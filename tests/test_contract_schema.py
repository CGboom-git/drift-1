from pact_drift.contract_generator import generate_global_tool_contracts
from pact_drift.contracts import contracts_to_jsonable, global_contracts_from_json


def test_contract_round_trip_and_banking_roles():
    schemas = [{"name": "send_money", "description": "Transfer money", "parameters": {"properties": {"recipient": {}, "amount": {}, "subject": {}, "date": {}}}}]
    contracts = generate_global_tool_contracts(schemas)
    restored = global_contracts_from_json(contracts_to_jsonable(contracts))
    send_money = restored.tools["send_money"]
    assert send_money.tool_type == "ACTION"
    assert send_money.arguments["recipient"].role == "target"
    assert send_money.arguments["amount"].role == "financial_amount"
    assert not send_money.arguments["date"].allow_model_generated
