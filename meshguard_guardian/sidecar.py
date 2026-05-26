from __future__ import annotations

from typing import Any, Callable, Mapping

from .audit import AuditEvent, AuditWAL
from .policy import EvaluationResult, LastKnownGoodPolicyCache, PolicyUnavailable


RemoteEvaluator = Callable[[Mapping[str, Any]], EvaluationResult | Mapping[str, Any]]


class GuardianSidecar:
    def __init__(
        self,
        tenant_id: str,
        policy_cache: LastKnownGoodPolicyCache,
        audit_wal: AuditWAL,
        *,
        remote_evaluator: RemoteEvaluator | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.policy_cache = policy_cache
        self.audit_wal = audit_wal
        self.remote_evaluator = remote_evaluator

    def evaluate(self, request: Mapping[str, Any]) -> EvaluationResult:
        try:
            result = self._evaluate_remote(request)
        except Exception as exc:
            result = self._evaluate_disconnected(request, exc)

        self.audit_wal.append(
            AuditEvent(
                tenant_id=str(request.get("tenant_id") or self.tenant_id),
                agent_id=str(request.get("agent_id") or ""),
                action=str(request.get("action") or ""),
                decision=result.decision,
                reason=result.reason,
                policy_version=result.policy_version,
                offline=result.offline,
                context=dict(request.get("context") or {}),
            )
        )
        return result

    def _evaluate_remote(self, request: Mapping[str, Any]) -> EvaluationResult:
        if self.remote_evaluator is None:
            raise PolicyUnavailable("remote evaluator is not configured")
        raw = self.remote_evaluator(request)
        if isinstance(raw, EvaluationResult):
            return raw
        return EvaluationResult(
            decision=str(raw.get("decision", "DENY")).upper(),
            reason=str(raw.get("reason") or ""),
            policy_version=str(raw.get("policy_version") or ""),
            matched_rule=str(raw.get("matched_rule") or ""),
            offline=False,
        )

    def _evaluate_disconnected(
        self,
        request: Mapping[str, Any],
        failure: Exception,
    ) -> EvaluationResult:
        try:
            policy = self.policy_cache.load(allow_stale=True)
        except PolicyUnavailable as cache_failure:
            return EvaluationResult(
                decision="DENY",
                reason=f"MeshGuard unavailable and no usable cached policy: {cache_failure}",
                offline=True,
            )

        result = policy.evaluate(request, offline=True)
        return EvaluationResult(
            decision=result.decision,
            reason=f"{result.reason}; evaluated with last-known-good policy after gateway error: {failure}",
            policy_version=result.policy_version,
            matched_rule=result.matched_rule,
            offline=True,
        )
