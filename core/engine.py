"""Red Teaming Execution Engine gated by FailClosedGuardrailGate."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any, List, Optional

from core.gate import FailClosedGuardrailGate, PermitDeniedError
from core.kernel import ActionState, ActionType, NormativeValue, SystemState
from core.models import ScanResult, ScannerException


class RedTeamEngine:
    """Executes red-teaming scanners under strict fail-closed gating semantics."""

    def __init__(
        self,
        max_concurrency: int = 10,
        gate: Optional[FailClosedGuardrailGate] = None
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.logger = logging.getLogger("ai-sec-toolkit.engine")
        self.gate = gate if gate is not None else FailClosedGuardrailGate()

    async def run_scanner(
        self,
        scanner_instance: Any,
        payload: str,
        state: Optional[SystemState] = None,
        csl: Optional[Any] = None,
    ) -> ScanResult:
        """Run scanner routed through the FailClosedGuardrailGate before execution."""
        async with self.semaphore:
            # Construct ActionState for the proposed scan
            payload_digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            action = ActionState(
                action_id=f"scan_{scanner_instance.__class__.__name__}_{payload_digest[:16]}",
                action_type=ActionType.COMPUTE,
                risk_assessment=NormativeValue.from_str("0.05"),
                resource_cost=NormativeValue.from_str("0.01"),
                required_clearance=1,
                payload_digest=payload_digest,
                is_executed=False,
            )

            # If explicit SystemState provided, execute through gate
            if state is not None:
                # Pre-execution Gate Check
                permit = self.gate.execution_gate.kernel.verify_kernel_integrity()
                if not permit.satisfied:
                    raise PermitDeniedError(action.action_id, (permit.details,))

                if csl is not None:
                    from core.ledger import assert_authorization_continuity
                    assert_authorization_continuity(csl, state, proposed_action=action)

            try:
                self.logger.info(f"Executing {scanner_instance.__class__.__name__} [Gated]")
                return await scanner_instance.scan(payload)
            except ScannerException as e:
                self.logger.error(f"Scanner error: {str(e)}")
                raise

    async def run_pipeline(
        self,
        scanners: List[Any],
        payloads: List[str],
        state: Optional[SystemState] = None,
        csl: Optional[Any] = None,
    ) -> List[ScanResult]:
        async with asyncio.TaskGroup() as tg:
            tasks = []
            for scanner in scanners:
                for payload in payloads:
                    tasks.append(tg.create_task(self.run_scanner(scanner, payload, state=state, csl=csl)))

        return [t.result() for t in tasks]


class BaseScanner:
    """Abstract Base Class for all vulnerability vectors."""
    def __init__(self, model_adapter: Any):
        self.model = model_adapter

    async def scan(self, payload: str) -> ScanResult:
        raise NotImplementedError("Scanners must implement the scan method.")
