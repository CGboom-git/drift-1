from __future__ import annotations

from pact_drift.contract_generator_l2 import generate_global_tool_contracts_l2


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {
        "name": name,
        "description": description,
        "parameters": {"type": "object", "properties": properties},
    }


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def test_l2_generator_special_cases_send_money() -> None:
    contracts = generate_global_tool_contracts_l2(
        [
            _schema(
                "send_money",
                {
                    "recipient": _arg(),
                    "amount": {"type": "number"},
                    "subject": _arg(),
                    "date": _arg(),
                },
                "Send money to a recipient.",
            )
        ]
    )
    send_money = contracts.tools["send_money"]
    assert send_money.tool_type == "ACTION"
    assert send_money.check_mode == "full"
    assert send_money.args["recipient"].role == "target"
    assert send_money.args["amount"].role == "control"
    assert send_money.args["subject"].role == "content"
    assert send_money.args["date"].role == "control"
    assert "unrequested_transaction_history" in send_money.args["recipient"].F
    assert "unrequested_transaction_history" in send_money.args["amount"].F


def test_l2_generator_read_file_output_policy() -> None:
    contracts = generate_global_tool_contracts_l2([_schema("read_file", {"file_path": _arg()}, "Read a file.")])
    read_file = contracts.tools["read_file"]
    assert read_file.tool_type == "READ_SENSITIVE"
    assert read_file.output["raw_output_trust"] == "EXTERNAL"
    assert read_file.output["requires_structured_extraction"] is True


def test_l2_generator_get_iban_propagates_input_origins() -> None:
    contracts = generate_global_tool_contracts_l2([_schema("get_iban", {"name": _arg()}, "Get an IBAN.")])
    assert contracts.tools["get_iban"].output["propagate_input_origins"] is True


def test_l2_generator_transaction_history_is_sensitive() -> None:
    contracts = generate_global_tool_contracts_l2([_schema("get_most_recent_transactions", {"n": {"type": "integer"}})])
    assert contracts.tools["get_most_recent_transactions"].tool_type == "READ_SENSITIVE"


def test_l2_generator_delete_file_path_is_action_target() -> None:
    contracts = generate_global_tool_contracts_l2([_schema("delete_file", {"path": _arg()}, "Delete a file.")])
    delete_file = contracts.tools["delete_file"]
    assert delete_file.tool_type == "ACTION"
    assert delete_file.args["path"].role == "target"


def test_l2_generator_search_query_is_not_command() -> None:
    contracts = generate_global_tool_contracts_l2([_schema("search_web", {"query": _arg("search query")}, "Search public web.")])
    assert contracts.tools["search_web"].args["query"].role != "command"
