"""
langchain-nti: Drop-in NTI (Neutral Trust Infrastructure) security for LangChain.

This package enforces all 5 pillars of NTI on every LangChain tool execution:
  1. Zero-Trust Capability Enforcement
  2. NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
  3. BFT Multi-Agent Consensus
  4. Merkle-Chained Audit Trails
  5. P2P Agent Mesh & State Persistence

Usage:
    from langchain_nti import NTICallbackHandler
    from langchain.agents import AgentExecutor

    handler = NTICallbackHandler(agent_id="finance_agent")
    handler.grant_capability("execute_transfer")

    executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
"""

from langchain_nti.callback import NTICallbackHandler

__version__ = "0.1.0"
__all__ = ["NTICallbackHandler"]
