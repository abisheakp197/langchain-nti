"""
Unit tests for NTICallbackHandler and NTISecurityLayer.
"""

import asyncio
import pytest
import ube_foundation
from langchain_nti import NTICallbackHandler, NTISecurityLayer


def test_handler_initialization() -> None:
    handler = NTICallbackHandler(agent_id="test_agent")
    assert handler.agent_id == "test_agent"
    assert handler.strict is True
    assert handler.verify_tool_responses is False
    assert isinstance(handler.public_key_hex(), str)
    assert len(handler.public_key_hex()) > 0
    assert isinstance(handler.kyber_public_key_bytes(), bytes)
    assert len(handler.kyber_public_key_bytes()) > 0


def test_invalid_agent_id() -> None:
    with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
        NTICallbackHandler(agent_id="")

    with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
        NTICallbackHandler(agent_id=123)  # type: ignore[arg-type]


def test_key_injection() -> None:
    custom_key = ube_foundation.PqcKeyPair()
    handler = NTICallbackHandler(agent_id="injected_agent", pqc_key=custom_key)
    assert handler.public_key_hex() == custom_key.public_key_hex()


def test_grant_capability_validation() -> None:
    handler = NTICallbackHandler(agent_id="agent1")
    handler.grant_capability("test_cap")

    with pytest.raises(ValueError, match="capability must be a non-empty string"):
        handler.grant_capability("")

    with pytest.raises(ValueError, match="capability must be a non-empty string"):
        handler.grant_capability(None)  # type: ignore[arg-type]


def test_revoke_token() -> None:
    handler = NTICallbackHandler(agent_id="agent1")
    handler.revoke_token("token_123")

    with pytest.raises(ValueError, match="token_id must be a non-empty string"):
        handler.revoke_token("")


def test_register_voter_key() -> None:
    handler = NTICallbackHandler(agent_id="agent1")
    voter_kp = ube_foundation.PqcKeyPair()
    handler.register_voter_key("voter_01", voter_kp.get_public_key_bytes())

    with pytest.raises(ValueError, match="voter_id must be a non-empty string"):
        handler.register_voter_key("", b"keybytes")

    with pytest.raises(ValueError, match="public_key_bytes must be non-empty bytes"):
        handler.register_voter_key("voter1", b"")


def test_sign_str_and_bytes() -> None:
    handler = NTICallbackHandler(agent_id="sign_agent")
    sig1 = handler.sign("Hello string")
    sig2 = handler.sign(b"Hello bytes")

    assert isinstance(sig1, str) and len(sig1) > 0
    assert isinstance(sig2, str) and len(sig2) > 0


def test_non_strict_on_tool_start_and_end() -> None:
    handler = NTICallbackHandler(
        agent_id="non_strict_agent",
        strict=False,
        verify_tool_responses=True,
    )
    handler.on_tool_start(serialized={"name": "unauthorized_tool"}, input_str="data")
    handler.on_tool_end("Unsigned tool output")


def test_async_callbacks_direct() -> None:
    async def _run() -> None:
        handler = NTICallbackHandler(agent_id="async_direct_agent")
        handler.grant_capability("my_async_tool")

        await handler.aon_tool_start(serialized={"name": "my_async_tool"}, input_str="data")
        await handler.aon_tool_end("tool output")

    asyncio.run(_run())


def test_nti_security_layer_subclass() -> None:
    layer = NTISecurityLayer(agent_id="sec_agent")
    assert isinstance(layer, NTICallbackHandler)
    assert layer.agent_id == "sec_agent"
