from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


class PolicyUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class EvaluationResult:
    decision: str
    reason: str
    policy_version: str = ""
    matched_rule: str = ""
    offline: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def to_json(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "matched_rule": self.matched_rule,
            "offline": self.offline,
        }


@dataclass(frozen=True)
class Policy:
    version: str
    fetched_at: float
    rules: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    default_decision: str = "DENY"
    default_reason: str = "no policy rule matched"

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "Policy":
        rules = value.get("rules") or ()
        if not isinstance(rules, list):
            raise ValueError("policy rules must be a list")
        return cls(
            version=str(value.get("version") or ""),
            fetched_at=float(value.get("fetched_at") or time.time()),
            rules=tuple(dict(rule) for rule in rules),
            default_decision=_normalize_decision(value.get("default_decision", "DENY")),
            default_reason=str(value.get("default_reason") or "no policy rule matched"),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "fetched_at": self.fetched_at,
            "rules": [dict(rule) for rule in self.rules],
            "default_decision": self.default_decision,
            "default_reason": self.default_reason,
        }

    def evaluate(self, request: Mapping[str, Any], *, offline: bool = False) -> EvaluationResult:
        for rule in self.rules:
            if _rule_matches(rule, request):
                decision = _normalize_decision(rule.get("decision", rule.get("effect", "DENY")))
                rule_id = str(rule.get("id") or "")
                reason = str(rule.get("reason") or f"matched policy rule {rule_id}".strip())
                return EvaluationResult(
                    decision=decision,
                    reason=reason,
                    policy_version=self.version,
                    matched_rule=rule_id,
                    offline=offline,
                )
        return EvaluationResult(
            decision=self.default_decision,
            reason=self.default_reason,
            policy_version=self.version,
            offline=offline,
        )


class LastKnownGoodPolicyCache:
    def __init__(
        self,
        path: str | Path,
        *,
        policy_cache_ttl_s: int = 3600,
        disconnected_max_age_s: int = 86400,
        clock: Any = time.time,
    ) -> None:
        self.path = Path(path)
        self.policy_cache_ttl_s = policy_cache_ttl_s
        self.disconnected_max_age_s = disconnected_max_age_s
        self.clock = clock

    def save(self, policy: Policy | Mapping[str, Any]) -> Policy:
        materialized = policy if isinstance(policy, Policy) else Policy.from_json(policy)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(materialized.to_json(), sort_keys=True, separators=(",", ":"))
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(self.path.parent),
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_name = handle.name
        os.replace(tmp_name, self.path)
        return materialized

    def load(self, *, allow_stale: bool = False) -> Policy:
        if not self.path.exists():
            raise PolicyUnavailable("no last-known-good policy is cached")
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyUnavailable("cached policy is not valid JSON") from exc
        policy = Policy.from_json(raw)
        age = self.clock() - policy.fetched_at
        max_age = self.disconnected_max_age_s if allow_stale else self.policy_cache_ttl_s
        if age > max_age:
            raise PolicyUnavailable(
                f"cached policy age {age:.0f}s exceeds allowed age {max_age}s"
            )
        return policy


def _rule_matches(rule: Mapping[str, Any], request: Mapping[str, Any]) -> bool:
    if not _selector_matches(rule.get("agents"), str(request.get("agent_id") or "")):
        return False
    if not _selector_matches(rule.get("actions"), str(request.get("action") or "")):
        return False

    conditions = rule.get("conditions") or {}
    if not isinstance(conditions, Mapping):
        raise ValueError("rule conditions must be an object")
    for key, expected in conditions.items():
        if not _condition_matches(_lookup(request, str(key)), expected):
            return False
    return True


def _selector_matches(selector: Any, value: str) -> bool:
    if selector in (None, "*"):
        return True
    if isinstance(selector, str):
        return selector == value
    if isinstance(selector, list):
        return "*" in selector or value in {str(item) for item in selector}
    return False


def _condition_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return actual in expected
    if isinstance(expected, Mapping):
        if "equals" in expected and actual != expected["equals"]:
            return False
        if "in" in expected and actual not in expected["in"]:
            return False
        if "exists" in expected and (actual is not None) != bool(expected["exists"]):
            return False
        if "lte" in expected and not _numeric_compare(actual, expected["lte"], lambda a, b: a <= b):
            return False
        if "gte" in expected and not _numeric_compare(actual, expected["gte"], lambda a, b: a >= b):
            return False
        return True
    return actual == expected


def _numeric_compare(actual: Any, expected: Any, op: Any) -> bool:
    try:
        return bool(op(float(actual), float(expected)))
    except (TypeError, ValueError):
        return False


def _lookup(value: Mapping[str, Any], dotted_key: str) -> Any:
    current: Any = value
    for part in dotted_key.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


def _normalize_decision(value: Any) -> str:
    decision = str(value).upper()
    if decision not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}:
        raise ValueError(f"invalid policy decision: {decision}")
    return decision
