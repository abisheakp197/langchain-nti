"""
NTI Callback Handler for LangChain.
Intercepts tool starts, evaluates all 5 pillars of NTI policy, and blocks unauthorized or tampered actions.
"""

import json
import uuid
from typing import Any
from uuid import UUID

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
        from langchain_nti import NTICallbackHandler

        handler = NTICallbackHandler(agent_id="finance_agent")
        handler.grant_capability("execute_transfer")
    """

    raise_error: bool = True

    def __init__(
        self,
        agent_id: str,
        strict: bool = True,
        pqc_key: Any | None = None,
        verify_tool_responses: bool = False,
    ) -> None:
        """
        Args:
            agent_id: Unique identifier for this agent.
            strict: If True, raises PermissionError on denied or unverified actions.
                    If False, logs or records the decision and continues.
            pqc_key: Optional pre-existing PqcKeyPair instance for key injection.
            verify_tool_responses: If True, requires all incoming tool responses
                                   in on_tool_end to carry valid PQC signatures.
        """
        super().__init__()
        from ube_foundation import PqcKeyPair, TrustEngine  # type: ignore[import-untyped]

        if not agent_id or not isinstance(agent_id, str):
            raise ValueError("agent_id must be a non-empty string")

        self.agent_id: str = agent_id
        self.strict: bool = strict
        self.verify_tool_responses: bool = verify_tool_responses
        self.raise_error = True

        # Pillar 1 + 3 + 4 + 5: TrustEngine handles capabilities, BFT voter registry,
        # Merkle audit chain, and P2P mesh state.
        self.engine: TrustEngine = TrustEngine()

        # Pillar 2: Post-quantum keypair (Dilithium5 signatures + Kyber1024 KEM)
        if pqc_key is not None:
            self.pqc_key: PqcKeyPair = pqc_key
        else:
            self.pqc_key = PqcKeyPair()

    # --- Pillar 1: Zero-Trust Capability Enforcement ---
    def grant_capability(self, capability: str) -> None:
        """Grant a capability to this agent. Every action requires an explicit grant."""
        if not capability or not isinstance(capability, str):
            raise ValueError("capability must be a non-empty string")
        self.engine.grant(self.agent_id, capability)

    def revoke_token(self, token_id: str) -> None:
        """Revoke a capability token so it can no longer authorize actions."""
        if not token_id or not isinstance(token_id, str):
            raise ValueError("token_id must be a non-empty string")
        self.engine.revoke_token(token_id)

    # --- Pillar 2: NIST Post-Quantum Cryptography ---
    def public_key_hex(self) -> str:
        """Return this agent's Dilithium5 public key in hex."""
        return str(self.pqc_key.public_key_hex())

    def kyber_public_key_bytes(self) -> bytes:
        """Return this agent's Kyber1024 public key bytes for envelope encryption."""
        return bytes(self.pqc_key.get_kyber_public_key_bytes())

    def sign(self, message: bytes | str) -> str:
        """Sign a message with this agent's Dilithium5 private key."""
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
        sig = self.pqc_key.sign(msg_bytes)
        return sig.hex() if isinstance(sig, bytes) else str(sig)

    def sign_output(self, data: str | bytes) -> dict[str, Any]:
        """Sign a tool or agent output payload with Dilithium5 PQC signature."""
        data_str = data.decode("utf-8") if isinstance(data, bytes) else str(data)
        data_bytes = data_str.encode("utf-8")
        sig_str = self.sign(data_bytes)
        return {
            "data": data_str,
            "signature": sig_str,
            "pqc_public_key": self.public_key_hex(),
            "agent_id": self.agent_id,
        }

    def verify_output(self, payload: Any) -> bool:
        """
        Verify a signed output payload against this agent's PQC key.

        Returns True if signature is valid, False otherwise.
        """
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                return False

        if not isinstance(payload, dict):
            return False

        data = payload.get("data")
        sig = payload.get("signature")

        if data is None or sig is None:
            return False

        data_bytes = str(data).encode("utf-8")
        sig_str = str(sig)

        try:
            return bool(self.pqc_key.verify(data_bytes, sig_str))
        except (ValueError, TypeError, AttributeError, RuntimeError):
            return False

    def sign_tool_response(self, response: str | bytes) -> dict[str, Any]:
        """Convenience method to sign a tool response."""
        return self.sign_output(response)

    def verify_tool_response(self, response: Any) -> bool:
        """Convenience method to verify a tool response signature."""
        return self.verify_output(response)

    # --- Pillar 3: BFT Multi-Agent Consensus ---
    def register_voter_key(self, voter_id: str, public_key_bytes: bytes | list[int]) -> None:
        """Register a BFT voter's public key for consensus verification."""
        if not voter_id or not isinstance(voter_id, str):
            raise ValueError("voter_id must be a non-empty string")
        if not public_key_bytes:
            raise ValueError("public_key_bytes must be non-empty bytes")
        key_bytes = bytes(public_key_bytes) if not isinstance(public_key_bytes, bytes) else public_key_bytes
        self.engine.register_voter_key(voter_id, key_bytes)

    # --- Interceptor Methods for LangChain Callback Handler ---
    def on_tool_start(
        self,
        serialized: dict[str, Any] | None,
        input_str: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a LangChain tool starts.

        Builds an ActionRequest, evaluates it against the NTI TrustEngine,
        and raises PermissionError if the decision is Deny.
        """
        tool_name = "unknown_tool"
        if serialized and isinstance(serialized, dict):
            tool_name = str(serialized.get("name", "unknown_tool"))

        if not isinstance(input_str, str):
            input_str = str(input_str)

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

        try:
            decision_raw = self.engine.evaluate(json.dumps(req))
            decision = json.loads(decision_raw)
        except Exception as err:
            if self.strict:
                raise PermissionError(f"NTI Security Policy Evaluation Error: {err}") from err
            return

        if decision.get("decision") != "Allow":
            reason = decision.get("reason", "Unknown reason")
            if self.strict:
                raise PermissionError(f"NTI Security Denied Action: {reason}")

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a LangChain tool completes execution.

        If verify_tool_responses is True, validates the PQC signature before
        allowing data to re-enter the LangChain agent loop.
        """
        if self.verify_tool_responses and not self.verify_output(output) and self.strict:
            raise PermissionError(
                "NTI Security Denied Action: Unsigned or tampered tool response"
            )

    async def aon_tool_start(
        self,
        serialized: dict[str, Any] | None,
        input_str: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Async callback when a LangChain tool starts."""
        self.on_tool_start(
            serialized=serialized,
            input_str=input_str,
            run_id=run_id,
            parent_run_id=parent_run_id,
            tags=tags,
            metadata=metadata,
            inputs=inputs,
            **kwargs,
        )

    async def aon_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Async callback when a LangChain tool completes execution."""
        self.on_tool_end(
            output,
            run_id=run_id,
            parent_run_id=parent_run_id,
            **kwargs,
        )


class NTISecurityLayer(NTICallbackHandler):
    """
    NTISecurityLayer is a high-level drop-in wrapper for LangChain agents.
    Inherits all security enforcement capabilities from NTICallbackHandler.
    """
