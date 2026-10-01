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
- authoritative VFP project/DBC/CDX knowledge: the host gathers authoritative
  project knowledge and emits a conforming producer-independent JSON metadata
  document into DBF_Anonymizer's public planning boundary (see
  [external-vfp-metadata-contract.md](external-vfp-metadata-contract.md)),
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

## The authoritative-metadata flow (completed P6-006 contract)

DBF_Anonymizer owns and ships the external VFP relationship/index metadata
consumer contract: a versioned, transport-neutral, producer-independent JSON
Schema is shipped inside the package and loaded through the public
`importlib.resources` resource path (see
[external-vfp-metadata-contract.md](external-vfp-metadata-contract.md)). The
current downstream pattern:

mcp-vfp9sp2-toolchain
→ gathers authoritative VFP/DBC/CDX project knowledge,
→ emits a conforming producer-independent transport-neutral JSON metadata document,
→ passes it into DBF_Anonymizer through the existing public synchronous API
  (`build_plan(..., relationship_document=<envelope>)`),
→ DBF_Anonymizer validates it fail-closed, preserves the supplied structured
  producer provenance and external schema version, fingerprints it, and uses
  authoritative claims only under the implemented per-claim
  provenance/authority/assurance/verification rules.

An injected verified index metadata claim does NOT by itself prove that an
output CDX/IDX was rebuilt: output index validity still requires the
appropriate authoritative backend rebuild/verification evidence. External
metadata does NOT recreate source DBC semantics in standalone output.

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