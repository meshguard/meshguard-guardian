# meshguard-guardian

OSS sidecar for local policy enforcement, streaming inspection, disconnected audit WAL, and last-known-good policy operation.

## Deployment Targets

- Kubernetes sidecar.
- ECS sidecar.
- Standalone VM binary.
- Air-gapped bundle component.

## Runtime Components

- Helm chart directory.
- Last-known-good policy cache for disconnected operation.
- Deterministic local policy evaluator for sidecar fallback.
- Durable JSONL audit WAL with replay-and-truncate semantics.
- Streaming inspection protocol matrix tracked in the MeshGuard PRD.

## Development

```bash
python3 -m pytest -q
python3 -m compileall -q meshguard_guardian
```
