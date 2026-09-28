# mcp-vfp9sp2-toolchain consumer integration

DBF_Anonymizer is a synchronous, transport-neutral library and CLI. It is NOT
an MCP server, and it ships no transport, no authentication or authorization,
no allowed-root/path policy and no asynchronous job orchestration. Those
concerns belong to the downstream host — in this project family that host is
the mcp-vfp9sp2-toolchain project, which owns:

- MCP transport and protocol serving,
- authentication and authorization,
- allowed-root/path policy for filesystem access,
- asynchronous/job orchestration,
- authoritative VFP project/DBC/CDX knowledge (when a frozen authoritative
  metadata contract becomes available; see
  [limits-and-integrity.md](limits-and-integrity.md) for the current
  P6-006 status),
- server-side policy for consumers.

DBF_Anonymizer does not import mcp-vfp9sp2-toolchain, and the boundary is
one-directional: a downstream host may call DBF_Anonymizer's public Python
API; DBF_Anonymizer never calls the host.

## The thin adapter pattern

A downstream host wraps the public synchronous API in its own thin adapter.
The repository contains a minimal reference adapter at
[examples/consumer_adapter.py](../examples/consumer_adapter.py); its essence:

```python
import dbf_anonymizer as public


def run_workflow(source, output, vault, *, relationship_document=None):
    plan = public.build_plan(source, output, vault, relationship_document=relationship_document)
    preflight_result = public.preflight(plan)
    if not preflight_result.ready:
        # Refused plans are returned to the host without any mutable work.
        return preflight_result
    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    return verification
```

The adapter is deliberately thin: DBF_Anonymizer calls are synchronous and
return typed public results or raise the typed public error hierarchy
(`AnonymizerError` and its categories — see
[errors-1.0.md](errors-1.0.md)). The host converts results/exceptions into
whatever its transport needs.

## What the downstream host supplies (and DBF_Anonymizer does not)

- policy and path authorization (which paths a consumer may touch),
- asynchronous orchestration, timeouts, job queues, retries,
- transport (for example MCP) and session/user controls,
- authoritative VFP/DBC/CDX project metadata when available,
- logging/telemetry policy for its own layer.

DBF_Anonymizer stays transport-neutral: the same synchronous calls serve a
CLI invocation, a test harness, or a wrapped server without any DBF_Anonymizer
change.

## What must not be built into DBF_Anonymizer

- MCP server code or any server framework (DBF_Anonymizer is not a server),
- authentication/authorization code,
- consumer-specific server policy,
- async orchestration.

Requests for those belong to the host project. Documentation, examples and
tests in this repository must keep the boundary explicit — the documentation
contract tests assert that DBF_Anonymizer is described as transport-neutral
and not an MCP server.