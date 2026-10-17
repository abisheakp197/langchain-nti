"""
Negative-path validation tests for langchain-nti.
"""

from unittest.mock import MagicMock
import pytest
from langchain_nti import NTICallbackHandler


def test_on_tool_start_with_none_serialized() -> None:
    handler = NTICallbackHandler(agent_id="neg_agent", strict=True)

    with pytest.raises(PermissionError, match="NTI Security Denied Action: no cap"):
        handler.on_tool_start(serialized=None, input_str="raw_input")

    handler.grant_capability("unknown_tool")
    handler.on_tool_start(serialized=None, input_str="raw_input")


def test_on_tool_start_non_string_input() -> None:
    handler = NTICallbackHandler(agent_id="neg_agent", strict=True)
    handler.grant_capability("my_tool")

    handler.on_tool_start(serialized={"name": "my_tool"}, input_str=12345)  # type: ignore[arg-type]
    handler.on_tool_start(serialized={"name": "my_tool"}, input_str={"key": "val"})  # type: ignore[arg-type]


def test_on_tool_start_engine_evaluation_error() -> None:
    handler = NTICallbackHandler(agent_id="err_agent", strict=True)
    handler.engine = MagicMock()
    handler.engine.evaluate.side_effect = RuntimeError("Engine failure")

    with pytest.raises(PermissionError, match="NTI Security Policy Evaluation Error"):
        handler.on_tool_start(serialized={"name": "my_tool"}, input_str="test")

    handler.strict = False
    handler.on_tool_start(serialized={"name": "my_tool"}, input_str="test")


def test_empty_tool_output_verify() -> None:
    handler = NTICallbackHandler(agent_id="neg_agent")

    assert handler.verify_output("") is False
    assert handler.verify_output(None) is False
    assert handler.verify_output({}) is False


def test_on_tool_end_empty_output_strict() -> None:
    handler = NTICallbackHandler(
        agent_id="strict_agent",
        strict=True,
        verify_tool_responses=True,
    )

    with pytest.raises(PermissionError, match="Unsigned or tampered tool response"):
        handler.on_tool_end("")

    with pytest.raises(PermissionError, match="Unsigned or tampered tool response"):
        handler.on_tool_end(None)
