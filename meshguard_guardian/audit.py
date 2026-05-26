from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class AuditEvent:
    tenant_id: str
    agent_id: str
    action: str
    decision: str
    reason: str
    policy_version: str = ""
    offline: bool = False
    context: Mapping[str, Any] = field(default_factory=dict)
    observed_at: float = field(default_factory=time.time)

    def to_json(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "offline": self.offline,
            "context": dict(self.context),
            "observed_at": self.observed_at,
        }


class AuditWAL:
    """Durable JSONL audit write-ahead log used while the gateway is unavailable."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent | Mapping[str, Any]) -> None:
        payload = event.to_json() if isinstance(event, AuditEvent) else dict(event)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        events: list[dict[str, Any]] = []
        for line_number, raw in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid audit WAL JSON on line {line_number}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"invalid audit WAL event on line {line_number}")
            events.append(event)
        return events

    def replay(self, sink: Any, *, batch_size: int = 100) -> int:
        """Send WAL events to a sink and truncate only after every batch is accepted."""

        events = self.read_all()
        sent = 0
        for batch in _chunks(events, batch_size):
            sink(list(batch))
            sent += len(batch)
        self.truncate()
        return sent

    def truncate(self) -> None:
        self._atomic_write("")

    def _atomic_write(self, content: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(self.path.parent),
            delete=False,
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_name = handle.name
        os.replace(tmp_name, self.path)


def _chunks(events: list[dict[str, Any]], size: int) -> Iterable[list[dict[str, Any]]]:
    if size <= 0:
        raise ValueError("batch_size must be positive")
    for index in range(0, len(events), size):
        yield events[index : index + size]
