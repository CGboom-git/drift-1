from __future__ import annotations

from pact_drift.ifc_contract_generator import generate_ifc_global_contract


def _schema(name: str, properties: dict[str, dict], description: str = "") -> dict:
    return {
        "name": name,
        "description": description,
        "parameters": {"type": "object", "properties": properties},
    }


def _arg(description: str = "") -> dict:
    return {"type": "string", "description": description}


def _generate(*schemas: dict):
    return generate_ifc_global_contract(list(schemas), "agentdojo", {"name": "agentdojo", "version": "v1"})


def test_ifc_generator_send_money_roles_and_scope() -> None:
    contract = _generate(_schema("send_money", {"recipient": _arg(), "amount": {"type": "number"}, "subject": _arg(), "date": _arg()}))
    send_money = contract.tools["send_money"]
    assert send_money.sink_scope == "financial"
    assert send_money.args["recipient"].sink_role == "target"
    assert send_money.args["amount"].sink_role == "control"
    assert send_money.args["subject"].sink_role == "content"
    assert send_money.args["date"].sink_role == "control"
    assert "unauthorized_tool_output" in send_money.args["amount"].deny_marks


def test_ifc_generator_workspace_writes_keep_user_private_content() -> None:
    contract = _generate(
        _schema("create_file", {"filename": _arg(), "content": _arg()}),
        _schema("append_to_file", {"file_id": _arg(), "content": _arg()}),
    )
    assert contract.tools["create_file"].sink_scope == "workspace"
    assert contract.tools["create_file"].args["content"].C_max == "USER_PRIVATE"
    assert contract.tools["append_to_file"].args["content"].C_max == "USER_PRIVATE"


def test_ifc_generator_public_posting_is_public_content_sink() -> None:
    contract = _generate(_schema("post_webpage", {"url": _arg(), "content": _arg()}))
    post_webpage = contract.tools["post_webpage"]
    assert post_webpage.sink_scope == "public"
    assert post_webpage.args["url"].sink_role == "target"
    assert post_webpage.args["content"].sink_role == "content"
    assert post_webpage.args["content"].C_max == "PUBLIC"
    assert "no_private_to_public_sink" in post_webpage.args["content"].flow_constraints


def test_ifc_generator_share_file_adds_object_confidentiality_controls() -> None:
    contract = _generate(_schema("share_file", {"file_id": _arg(), "user": _arg()}))
    file_id = contract.tools["share_file"].args["file_id"]
    assert "object_confidentiality_check" in file_id.flow_constraints
    assert "object_share_authorization" in file_id.declassifications


def test_ifc_generator_send_email_scope_and_content_roles() -> None:
    contract = _generate(_schema("send_email", {"to": _arg(), "subject": _arg(), "body": _arg()}))
    send_email = contract.tools["send_email"]
    assert send_email.sink_scope == "messaging"
    assert send_email.args["to"].sink_role == "target"
    assert send_email.args["subject"].sink_role == "content"
    assert send_email.args["body"].sink_role == "content"


def test_ifc_generator_search_query_is_not_command() -> None:
    contract = _generate(_schema("search_web", {"query": _arg("search query")}, "Search public web."))
    assert contract.tools["search_web"].args["query"].sink_role != "command"


def test_ifc_generator_update_password_uses_secret_credential() -> None:
    contract = _generate(_schema("update_password", {"password": _arg()}))
    password = contract.tools["update_password"].args["password"]
    assert password.sink_role == "credential"
    assert password.C_max == "SECRET"
