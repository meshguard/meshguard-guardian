from __future__ import annotations

from pathlib import Path

from meshguard_guardian import (
    AuditWAL,
    EvaluationResult,
    GuardianSidecar,
    LastKnownGoodPolicyCache,
    Policy,
    PolicyUnavailable,
)


def _policy(fetched_at: float = 100.0) -> Policy:
    return Policy.from_json(
        {
            "version": "policy-v1",
            "fetched_at": fetched_at,
            "rules": [
                {
                    "id": "deny-shell",
                    "decision": "DENY",
                    "agents": ["agent-1"],
                    "actions": ["tool:exec"],
                    "reason": "shell is blocked",
                },
                {
                    "id": "allow-read",
                    "decision": "ALLOW",
                    "agents": ["agent-1"],
                    "actions": ["ticket:read"],
                    "conditions": {"context.ticket.sensitivity": {"lte": 2}},
                    "reason": "low sensitivity ticket read",
                },
            ],
            "default_decision": "DENY",
        }
    )


def test_disconnected_sidecar_uses_last_known_good_policy(tmp_path: Path) -> None:
    cache = LastKnownGoodPolicyCache(
        tmp_path / "policy.json",
        policy_cache_ttl_s=10,
        disconnected_max_age_s=500,
        clock=lambda: 200.0,
    )
    cache.save(_policy())
    wal = AuditWAL(tmp_path / "audit.wal")

    def gateway_down(_request):
        raise TimeoutError("gateway timed out")

    sidecar = GuardianSidecar(
        "tenant-1",
        cache,
        wal,
        remote_evaluator=gateway_down,
    )

    result = sidecar.evaluate(
        {
            "tenant_id": "tenant-1",
            "agent_id": "agent-1",
            "action": "ticket:read",
            "context": {"ticket": {"sensitivity": 1}},
        }
    )

    assert result.allowed
    assert result.offline
    assert result.policy_version == "policy-v1"
    assert result.matched_rule == "allow-read"
    assert wal.read_all()[0]["offline"] is True


def test_disconnected_cache_rejects_policy_past_max_age(tmp_path: Path) -> None:
    cache = LastKnownGoodPolicyCache(
        tmp_path / "policy.json",
        policy_cache_ttl_s=10,
        disconnected_max_age_s=50,
        clock=lambda: 200.0,
    )
    cache.save(_policy(fetched_at=100.0))

    try:
        cache.load(allow_stale=True)
    except PolicyUnavailable as exc:
        assert "exceeds allowed age" in str(exc)
    else:
        raise AssertionError("expected stale policy rejection")


def test_remote_success_is_audited_and_does_not_use_cache(tmp_path: Path) -> None:
    cache = LastKnownGoodPolicyCache(tmp_path / "policy.json", clock=lambda: 200.0)
    wal = AuditWAL(tmp_path / "audit.wal")
    sidecar = GuardianSidecar(
        "tenant-1",
        cache,
        wal,
        remote_evaluator=lambda _request: EvaluationResult(
            decision="ALLOW",
            reason="gateway allowed",
            policy_version="remote-v2",
        ),
    )

    result = sidecar.evaluate({"agent_id": "agent-1", "action": "ticket:read"})

    assert result.allowed
    assert result.offline is False
    assert wal.read_all()[0]["policy_version"] == "remote-v2"


def test_audit_wal_replay_truncates_only_after_success(tmp_path: Path) -> None:
    wal = AuditWAL(tmp_path / "audit.wal")
    wal.append({"event_id": "1"})
    wal.append({"event_id": "2"})

    def failing_sink(_batch):
        raise RuntimeError("upload failed")

    try:
        wal.replay(failing_sink, batch_size=1)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected replay failure")

    assert [event["event_id"] for event in wal.read_all()] == ["1", "2"]

    batches = []
    sent = wal.replay(lambda batch: batches.append(batch), batch_size=1)

    assert sent == 2
    assert [batch[0]["event_id"] for batch in batches] == ["1", "2"]
    assert wal.read_all() == []
