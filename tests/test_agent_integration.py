"""
Integration tests using real LangChain tools and agents (zero mocks for LangChain logic).
"""

import asyncio
import pytest
from langchain_core.tools import tool
from langchain_nti import NTICallbackHandler, NTISecurityLayer


@tool
def calculate_sum(a: int, b: int) -> int:
    """Calculates the sum of two integers."""
    return a + b


@tool
def database_query(query: str) -> str:
    """Executes a database query."""
    return f"Results for {query}"


def test_real_tool_granted_capability_succeeds() -> None:
    handler = NTICallbackHandler(agent_id="agent_1")
    handler.grant_capability("calculate_sum")

    res = calculate_sum.invoke({"a": 10, "b": 20}, config={"callbacks": [handler]})
    assert res == 30


def test_real_tool_ungranted_capability_denied() -> None:
    handler = NTICallbackHandler(agent_id="agent_1", strict=True)

    with pytest.raises(PermissionError, match="NTI Security Denied Action: no cap"):
        calculate_sum.invoke({"a": 10, "b": 20}, config={"callbacks": [handler]})


def test_real_tool_non_strict_mode() -> None:
    handler = NTICallbackHandler(agent_id="agent_1", strict=False)

    res = calculate_sum.invoke({"a": 5, "b": 5}, config={"callbacks": [handler]})
    assert res == 10


def test_async_real_tool_execution() -> None:
    async def _run() -> None:
        handler = NTICallbackHandler(agent_id="async_agent")
        handler.grant_capability("database_query")

        res = await database_query.ainvoke({"query": "SELECT * FROM users"}, config={"callbacks": [handler]})
        assert res == "Results for SELECT * FROM users"

    asyncio.run(_run())


def test_async_real_tool_ungranted_denied() -> None:
    async def _run() -> None:
        handler = NTICallbackHandler(agent_id="async_agent", strict=True)

        with pytest.raises(PermissionError, match="NTI Security Denied Action: no cap"):
            await database_query.ainvoke({"query": "DROP TABLE users"}, config={"callbacks": [handler]})

    asyncio.run(_run())


def test_nti_security_layer_real_tool() -> None:
    layer = NTISecurityLayer(agent_id="layer_agent")
    layer.grant_capability("calculate_sum")

    res = calculate_sum.invoke({"a": 100, "b": 200}, config={"callbacks": [layer]})
    assert res == 300
