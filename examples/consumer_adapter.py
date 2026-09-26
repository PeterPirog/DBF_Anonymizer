"""Transport-neutral synchronous consumer adapter for DBF_Anonymizer.

An external host can wrap this function in its own transport, authorization,
path policy, timeout, or job orchestration layer.  This module deliberately
knows nothing about those concerns and imports only the public package root.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import dbf_anonymizer as public


@dataclass(frozen=True, slots=True)
class ConsumerWorkflowResult:
    """Typed public results produced by one synchronous consumer call."""

    plan: public.Plan
    preflight: public.PreflightResult
    pseudonymization: public.PseudonymizationResult | None
    verification: public.VerificationResult | None


def run_consumer_workflow(
    source: str | Path,
    output: str | Path,
    vault: str | Path,
    *,
    policy: Mapping[str, Any] | None = None,
    relationship_document: Mapping[str, Any] | None = None,
    workers: int = 1,
) -> ConsumerWorkflowResult:
    """Plan, preflight, pseudonymize, and verify through the public API.

    A refused preflight is returned to the host without starting the mutable
    operation.  Transport-specific conversion of the typed result or a raised
    ``AnonymizerError`` belongs to the external host.
    """
    plan = public.build_plan(
        source,
        output,
        vault,
        policy,
        relationship_document=relationship_document,
    )
    preflight_result = public.preflight(plan)
    if not preflight_result.ready:
        return ConsumerWorkflowResult(
            plan=plan,
            preflight=preflight_result,
            pseudonymization=None,
            verification=None,
        )

    pseudonymization_result = public.pseudonymize(plan, workers=workers)
    verification_result = public.verify_dataset(
        pseudonymization_result,
        source=source,
        vault=vault,
    )
    return ConsumerWorkflowResult(
        plan=plan,
        preflight=preflight_result,
        pseudonymization=pseudonymization_result,
        verification=verification_result,
    )
