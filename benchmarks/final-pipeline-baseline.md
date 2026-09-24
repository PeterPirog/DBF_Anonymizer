# Final pipeline benchmark — final-pipeline-synthetic-v1

> Reference measurement only, NOT a performance guarantee. Timings are
> environment-dependent and include the harness instrumentation
> overhead (timing wrappers, sqlite activity observation and the
> tracemalloc peak scan). Regenerate with
> `python tools/final_pipeline_benchmark.py --output ... --summary ...`
> from a fresh disposable workspace.

## Workload facts

- workload: `final-pipeline-synthetic-v1` (version 1.0)
- workload source fingerprint: `0b35aef6ee737b82f9a8331cc0adf7a7b55ba6ec2e6c00f317edda9bba84095a`
- tables: 3
- records written: 4800
- source bytes: 521243
- workers: 4

## Environment

- package version: `1.0.0.dev0`
- dbfbridge version: `1.1.1`
- python version: `3.12.10`
- platform: `Windows-11-10.0.26200-SP0`

## Throughput

- wall (pseudonymize): 658.516652 s
- records per second: 7.28911

## Memory

- peak memory (tracemalloc, pseudonymize + verification): 2776175 bytes

## Storage

- output bytes: 521243
- vault bytes: 1720320
- sqlite bytes: 1720320
- temporary peak bytes (sampled engine-owned transient artifacts): 701750

## Timing

- sqlite time (vault/spool/evidence activity, measured): 474.637022 s
- DBF/FPT fresh write time (pass2 kernel, measured): 6.047244 s
- verification (public verify_dataset): 0.873175 s

## Index backend

- applicable: NO (P6 index backend does not exist yet)
- timing: NOT_APPLICABLE (null)
