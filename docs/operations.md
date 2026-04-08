# Operations Guide

## CI

- Run `go test ./...` as the main correctness gate.
- Run `go test ./cmd/k8doc -run TestPublishedOutputContract` to guard the JSON output contract.
- Run `go test ./internal/diagnostics -run 'Test(PagedList|ListPodsCached|CollectCapabilityPreflight|TransientError|IssuePolicy)'` to validate runtime guardrails and signal policy.
- Run `go test ./internal/diagnostics -run '^$' -bench 'Benchmark(PagedList|ListPodsCached|NormalizeIssues)' -benchmem` to record runtime regression metrics.

## In-Cluster

- Apply one of the RBAC profiles in `deploy/rbac/` depending on scope.
- Run with `--output json` for machine-readable artifact collection.
- Use `--enable-active-probes` and `--enable-host-network-probes` only when the execution environment is allowed to reach API-proxy or host-network targets.

## Status Semantics

- `partial`: the check or section produced usable output but one or more required operations failed.
- `skipped`: the check was blocked by RBAC or policy and could not run normally.
- `not-applicable`: the check does not make sense for the selected scope, such as namespace-only execution for cluster-wide observability scans.

## Runtime Guardrails

- `--list-chunk-size` and `--max-list-items` control memory usage for large inventories.
- `--max-concurrent-checks` and `--max-concurrent-requests` cap API pressure.
- `--retry-attempts`, `--retry-backoff-ms`, and `--slow-operation-threshold-ms` help detect regressions in transient failure handling and latency.