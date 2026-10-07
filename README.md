# langchain-nti

**Full 5-pillar post-quantum security for LangChain agents, powered by NTI (Neutral Trust Infrastructure).**

[![PyPI](https://img.shields.io/pypi/v/langchain-nti.svg)](https://pypi.org/project/langchain-nti/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Install

pip install langchain-nti

## Quick Start

from langchain.agents import AgentExecutor
from langchain_nti import NTICallbackHandler

# Attach NTI to any LangChain agent
handler = NTICallbackHandler(agent_id="finance_agent")
handler.grant_capability("execute_transfer")

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[handler],
)

Every tool call is now cryptographically verified before execution.

## What It Enforces — All 5 Pillars of NTI

| Pillar | What It Does |
|---|---|
| **1. Zero-Trust Capability Enforcement** | Agents have zero inherent permissions. Every action requires an explicit capability grant, evaluated in real-time with caveats (Expires, MaxExecutions, ValueLimit, PathRestricted). |
| **2. NIST Post-Quantum Cryptography** | Every request is signed with CRYSTALS-Dilithium5 (NIST Level 5). Envelope encryption uses CRYSTALS-Kyber1024 + ChaCha20Poly1305. |
| **3. BFT Multi-Agent Consensus** | Multi-agent decisions require threshold signature collection. Prevents single-agent prompt injection and rogue agent behavior. |
| **4. Merkle-Chained Audit Trails** | Every evaluated action is hashed into a SHA-256 Merkle audit chain. Tamper-proof compliance logs, verifiable via verify_history(). |
| **5. P2P Agent Mesh & State Persistence** | Cryptographic agent identity, key rotation, and X25519 DH handshakes. Audit trails persist to disk and self-verify on reload. |

## BFT Consensus Example

handler.register_voter_key("voter_01", voter_public_key_bytes)
handler.register_voter_key("voter_02", voter_public_key_bytes)
# Multi-agent consensus enforced automatically on evaluation.

## Why NTI

Autonomous LLM agents are prone to prompt injection, hallucinated function calls, and unconstrained action execution. NTI provides a cryptographically verifiable execution barrier in <1ms overhead, ensuring agents cannot execute unauthorized actions even if compromised at the prompt level.

## License

Apache License 2.0. See LICENSE.

## Links

- Core SDK (PyPI): https://pypi.org/project/ube-foundation/
- Core SDK (crates.io): https://crates.io/crates/ube-foundation
- Homepage: https://abisheakp197.github.io/Neutral-Trust-Infrastructure/
- Whitepaper: ./WHITEPAPER.md
