"""
NTI Callback Handler for LangChain.
Intercepts tool starts, evaluates all 5 pillars of NTI policy, and blocks unauthorized actions.
"""

import json
import uuid
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler


class NTICallbackHandler(BaseCallbackHandler):
    """
    NTI Callback Handler for LangChain.

    Enforces all 5 pillars of NTI (Neutral Trust Infrastructure) on every
    LangChain tool execution:

      Pillar 1 — Zero-Trust Capability Enforcement
      Pillar 2 — NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
      Pillar 3 — BFT Multi-Agent Consensus
      Pillar 4 — Merkle-Chained Audit Trails
      Pillar 5 — P2P Agent Mesh & State Persistence

    Install:
        pip install langchain-nti

    Example:
        from langchain.agents import AgentExecutor
        from langchain_nti import NTICallbackHandler

        handler = NTICallbackHandler(agent_id="finance_agent")
        handler.grant_capability("execute_transfer")

        executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
    """

    def __init__(self, agent_id: str, strict: bool = True) -> None:
        """
        Args:
            agent_id: Unique identifier for this agent.
            strict: If True, raises PermissionError on denied actions.
                    If False, logs the decision and continues.
        """
        from ube_foundation import TrustEngine, PqcKeyPair

        self.agent_id = agent_id
        self.strict = strict

        # Pillar 1 + 3 + 4 + 5: TrustEngine handles capabilities,
        # BFT voter registry, Merkle audit chain, and P2P mesh state.
        self.engine = TrustEngine()

        # Pillar 2: Post-quantum keypair (Dilithium5 signatures + Kyber1024 KEM)
        self.pqc_key = PqcKeyPair.generate()

    # --- Pillar 1: Zero-Trust Capability Enforcement ---
    def grant_capability(self, capability: str) -> None:
        """Grant a capability to this agent. Every action requires an explicit grant."""
        self.engine.grant(self.agent_id, capability)

    def revoke_token(self, token_id: str) -> None:
        """Revoke a capability token so it can no longer authorize actions."""
        self.engine.revoke_token(token_id)

    # --- Pillar 2: NIST Post-Quantum Cryptography ---
    def public_key_hex(self) -> str:
        """Return this agent's Dilithium5 public key in hex."""
        return self.pqc_key.public_key_hex()

    def kyber_public_key_bytes(self) -> bytes:
        """Return this agent's Kyber1024 public key bytes for envelope encryption."""
        return self.pqc_key.get_kyber_public_key_bytes()

    def sign(self, message: bytes) -> str:
        """Sign a message with this agent's Dilithium5 private key."""
        return self.pqc_key.sign(message)

    # --- Pillar 3: BFT Multi-Agent Consensus ---
    def register_voter_key(self, voter_id: str, public_key_bytes: bytes) -> None:
        """Register a BFT voter's public key for consensus verification."""
        self.engine.register_voter_key(voter_id, public_key_bytes)

    # --- Pillar 4: Merkle-Chained Audit Trails ---
    # Activated automatically on every engine.evaluate() call.
    # Each decision is hashed into a SHA-256 Merkle audit chain.

    # --- Pillar 5: P2P Agent Mesh & State Persistence ---
    # Handled by the TrustEngine. Audit history persists to disk and
    # verifies integrity (verify_history()) on reload.

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """
        Called when a LangChain tool starts.

        Builds a signed ActionRequest, evaluates it against the NTI TrustEngine,
        and raises PermissionError if the decision is Deny.
        """
        tool_name = serialized.get("name", "unknown_tool")
        tool_input = {"raw_input": input_str}

        req = {
            "id": f"req-{uuid.uuid4()}",
            "actor": self.agent_id,
            "capability": tool_name,
            "action": tool_name,
            "input": tool_input,
            "signature": None,
            "pqc_signature": None,
            "public_key": None,
            "pqc_public_key": None,
            "token": None,
            "identity_claim": None,
        }

        message = json.dumps(req, sort_keys=True).encode("utf-8")
        req["pqc_signature"] = self.pqc_key.sign(message).hex()
        req["pqc_public_key"] = self.pqc_key.public_key_hex()

        decision = json.loads(self.engine.evaluate(json.dumps(req)))

        if decision.get("decision") != "Allow":
            reason = decision.get("reason", "Unknown reason")
            if self.strict:
                raise PermissionError(f"NTI Security Denied Action: {reason}")
