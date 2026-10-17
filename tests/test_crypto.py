"""
Cryptographic correctness tests for langchain-nti.
"""

import json
import pytest
from langchain_nti import NTICallbackHandler


def test_sign_and_verify_valid_output() -> None:
    handler = NTICallbackHandler(agent_id="crypto_agent")
    signed_payload = handler.sign_output("Data payload 123")

    assert isinstance(signed_payload, dict)
    assert signed_payload["data"] == "Data payload 123"
    assert "signature" in signed_payload
    assert signed_payload["agent_id"] == "crypto_agent"

    assert handler.verify_output(signed_payload) is True
    assert handler.verify_tool_response(signed_payload) is True


def test_verify_output_json_string() -> None:
    handler = NTICallbackHandler(agent_id="crypto_agent")
    signed_payload = handler.sign_output("Data payload 123")
    json_str = json.dumps(signed_payload)

    assert handler.verify_output(json_str) is True


def test_tampered_output_blocked() -> None:
    handler = NTICallbackHandler(agent_id="crypto_agent")
    signed_payload = handler.sign_output("Data payload 123")

    tampered_payload = dict(signed_payload, data="Data payload TAMPERED")
    assert handler.verify_output(tampered_payload) is False


def test_unsigned_output_blocked() -> None:
    handler = NTICallbackHandler(agent_id="crypto_agent")
    unsigned_payloads = [
        "Plain text response",
        {"data": "No signature present"},
        {"signature": "1234"},
        12345,
        None,
    ]

    for payload in unsigned_payloads:
        assert handler.verify_output(payload) is False


def test_invalid_json_string_verify() -> None:
    handler = NTICallbackHandler(agent_id="crypto_agent")
    assert handler.verify_output("invalid json {{{") is False


def test_on_tool_end_with_verify_responses_enabled() -> None:
    handler = NTICallbackHandler(
        agent_id="strict_crypto_agent",
        strict=True,
        verify_tool_responses=True,
    )

    valid_signed = handler.sign_output("Valid tool response")
    handler.on_tool_end(valid_signed)

    with pytest.raises(PermissionError, match="Unsigned or tampered tool response"):
        handler.on_tool_end("Unsigned raw text response")

    tampered = dict(valid_signed, data="Tampered content")
    with pytest.raises(PermissionError, match="Unsigned or tampered tool response"):
        handler.on_tool_end(tampered)
