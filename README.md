# k8doc

Version: 0.0.2.6-beta

Minimal Kubernetes troubleshooter written in Go. It connects to your cluster, runs a bundle of quick health checks, and prints a compact table of findings with recommendations.

Beyond the base scan, `k8doc` can now explain grouped findings, diff against a baseline, build event timelines, focus on a namespace/app/node, trace dependency paths, evaluate upgrade/security/cost posture, apply custom rules, and emit shareable reports.

It also supports an incident-focused view, service-chain inspection, node-pool diagnostics, release readiness checks, SLO risk estimation with blast radius hints, built-in noise suppression, and multi-cluster comparison across kubeconfig contexts.

Recent versions also add a production-oriented execution model: checks now run in best-effort mode by default, partial failures are reported in structured execution metadata, optional report sections can degrade without aborting the scan, and active probes are disabled unless explicitly enabled.

## Checks
- Pods: scheduling failures, image pull errors, crash loops, OOM kills, repeated restarts
- GPU and accelerators: missing `nvidia.com/gpu` or `nvidia.com/mig-*` inventory on GPU-marked nodes, capacity vs allocatable mismatches, missing NVIDIA device plugin or unavailable GPU Operator daemonsets, GPU pod `requests`/`limits` mistakes, taint/toleration and affinity mismatches, scheduler events such as `Insufficient nvidia.com/gpu`, driver/CUDA/runtime mismatch signals, missing DCGM-style observability, and MIG/time-slicing or shared-GPU profile mismatches
- Runtime and behavioral: suspicious restart patterns, recent exec/debug activity, ephemeral containers, newly launched privileged pods, crypto-mining or suspicious outbound markers, unusual listening ports, namespace pod churn, unexpected service account token mounts, unusual CronJobs, and unexpected cluster-wide DaemonSets
- Pod security: privileged containers, privilege escalation, root execution, missing `runAsNonRoot`, host namespace sharing, hostPath volumes, dangerous capabilities, missing capability drops, seccomp/AppArmor/SELinux gaps, writable root filesystems, unsafe proc mounts/sysctls, runtime socket mounts, ephemeral debug containers, and Pod Security Admission namespace drift/violations
- Secrets: encryption at rest coverage, TLS secret age and expiry hygiene, secret rotation cadence, unused or over-shared secrets, secret-in-env exposure, ConfigMap credential leaks, weak certificate crypto, stale docker registry credentials, and plain cloud credentials without rotation metadata
- Config and data exposure: sensitive ConfigMaps, verbose logging with secret-sourced config, env vars carrying tokens/keys/passwords, public dashboards or admin UIs, public metrics/debug/pprof endpoints without obvious auth, and labels/annotations leaking excessive metadata
- Network security: namespaces without NetworkPolicy, missing default deny ingress/egress, overly broad policies, sensitive workloads reachable too broadly, secret-bearing workloads with unrestricted egress, overly open DNS egress, weak webhook network isolation, ingress controllers exposing admin ports, and public LoadBalancer services without allowlists
- Storage security: broad PVC access modes, encryption-at-rest gaps, over-privileged CSI drivers, risky volume snapshot retention, shared RWX volumes, sensitive hostPath storage mounts, sensitive data on insecure storage classes, public backup target hints, stale unattached volumes, and reclaim-policy leakage risks
- Multi-tenancy: namespace isolation gaps, cross-namespace secret/config access, shared ingress and gateway routes, unisolated shared node pools, tenant workloads with host access, tenant access to cluster-scoped controls, broad cross-namespace list/watch, and mixed CI/CD plus runtime identities
- Managed Kubernetes: managed control-plane endpoint exposure, IAM-to-Kubernetes mapping drift hints, workload identity gaps, node role/profile review, metadata service exposure from pods, public cloud resources linked to the cluster, node pool perimeter review, and managed add-on hygiene
- Observability and detection: audit logging coverage, alerting gaps for RBAC/privileged pods/exec/secrets/webhooks, runtime detection tooling presence, drift detection, and manifest integrity monitoring signals
- Policy and compliance: ownership/classification metadata, mandatory securityContext and NetworkPolicy coverage, required PDBs and resource requests/limits for critical workloads, baseline hardening gaps, deprecated API usage, and exception registry hygiene
- Image policy and registry reachability: `imagePullPolicy`, missing `imagePullSecrets`, and registry endpoint reachability from the diagnostic host
- Nodes: NotReady, memory/disk pressure, network unavailable, kubelet anonymous auth/webhook authn-authz/read-only port misconfigurations, stale kubelet certificates, public node management exposure, SSH reachability, stale joined nodes, reachable cordoned nodes, suspicious workload-pinning labels/taints, and hostPath mounts exposing kubelet state or host credentials
- Scheduling: cordoned nodes, taint/toleration mismatches for pending pods
- Events: recent warning events for fast triage
- Trends: recent eviction and preemption spikes
- Controllers: Deployments/DaemonSets/ReplicaSets/Jobs/CronJobs availability and failures
- Workload lifecycle: paused deployments and workloads scaled to zero
- API server and etcd: readyz/livez probes, latency, and etcd DB size hints
- API exposure: public API endpoint detection, managed-cluster public endpoint hints, best-effort perimeter verification reminder, kubeconfig credentials found in secrets/configmaps, and legacy long-lived service account token detection
- RBAC: cluster-admin bindings, wildcard roles, `system:authenticated` or `system:unauthenticated` grants, over-broad ClusterRoleBindings, dangerous service account privileges, escalation verbs, unused privileged service accounts, default service account drift, external identity group review, and privileged service accounts in system namespaces
- Service accounts and tokens: automount defaults, default SA usage in production namespaces, legacy secret-backed tokens, overlong projected tokens, pods with unnecessary SA tokens, workload identity/IRSA/GKE WI/Azure WI misconfiguration hints, and service accounts that can read secrets across namespaces
- Control plane pods: scheduler/controller-manager readiness plus lightweight metrics signals
- Control plane security: apiserver/etcd/scheduler/controller-manager flags, anonymous auth, RBAC/authz mode, admission plugins, audit logging, secret encryption at rest, etcd TLS-only settings, control-plane certificate expiry/chain checks, kubelet CSR rotation hints, and deprecated API usage from apiserver metrics
- Webhooks: missing `caBundle`, expired CA or serving certs, fail-open vs fail-closed risk, overly broad rules, long timeouts, unavailable endpoints, externally exposed admission services, mutating pod/security-context injection risk, sensitive secret/serviceaccount/RBAC scopes without explicit controls, and probe latency
- Certificates: expiring TLS secrets and webhook CA bundles
- CNI/CSI: health of common CNI daemonsets, CSI daemonsets, and registered CSI drivers
- DNS: CoreDNS deployment availability, kube-dns endpoints, and DNS proxy latency
- Storage: PVC/PV binding failures, orphaned PVs, storage class presence, and volume attachment errors
- Resource quotas: namespace quota exhaustion and near-limit signals
- Ingress: controller availability, load balancer status, backend service/endpoints, ingress and Gateway API TLS coverage, expired/self-signed or weak edge certificates, legacy TLS policy/ciphers, missing HSTS or insecure redirects, public admin paths, wildcard host exposure, dangerous controller annotations, public internal-only LoadBalancers, sensitive NodePort services, and TLS handshake latency
- Autoscaling: HPA condition failures, missing metrics, and stalled scaling
- PDBs: disruption exhaustion, empty selectors, and overlapping selectors

## Quick Start

### Build And Run

| Command | Description |
|---|---|
| `go run ./cmd/k8doc --kubeconfig ~/.kube/config --context my-cluster --namespace default` | Run `k8doc` directly from source against one namespace. |
| `go build -o bin/k8doc ./cmd/k8doc` | Build the binary into `./bin/k8doc`. |
| `./bin/k8doc --kubeconfig ~/.kube/config --context my-cluster` | Run the compiled binary against the selected cluster context. |
| `./bin/k8doc --help` | Show all supported flags and defaults. |

### Development Commands

| Command | Description |
|---|---|
| `go test ./...` | Run the full test suite for the repository. |
| `go test ./cmd/k8doc -run TestPublishedOutputContract` | Verify the published JSON schema and golden report fixture stay in sync. |
| `go test ./internal/diagnostics -run 'Test(PagedList|ListPodsCached|CollectCapabilityPreflight|TransientError|IssuePolicy)'` | Run runtime guardrail, scale, and signal policy regression tests. |
| `go test ./internal/diagnostics -run '^$' -bench 'Benchmark(PagedListLargeInventory|ListPodsCachedReuse|NormalizeIssuesPolicy)' -benchmem` | Record runtime benchmark metrics for API pressure, allocations, and normalization cost. |
| `go test ./... -coverprofile=cover.out` | Run all tests and write a coverage profile to `cover.out`. |
| `go tool cover -func=cover.out` | Print coverage by function and the total statement coverage. |
| `go tool cover -html=cover.out` | Open an HTML coverage report for local inspection. |
| `go mod tidy` | Sync and clean module dependencies. |

### Common Run Examples

| Command | Description |
|---|---|
| `./bin/k8doc --checks pods,nodes` | Run only pod and node diagnostics. |
| `./bin/k8doc --checks gpu,pods,nodes --mode incident` | Triage GPU or AI-node placement, plugin, and runtime issues together with core pod/node health. |
| `./bin/k8doc --output json --enable-active-probes --probe-target-classes dns,webhook,controlplane` | Keep the scan API-first but allow selected active API-proxy probes. |
| `./bin/k8doc --output json --enable-host-network-probes --probe-target-classes ingress,registry,node --tls-probe-mode verify` | Enable host-network reachability and TLS verification probes explicitly. |
| `./bin/k8doc --list-chunk-size 250 --max-list-items 50000 --max-concurrent-checks 4 --max-concurrent-requests 8` | Run with explicit scaling guardrails for large clusters. |
| `./bin/k8doc --retry-attempts 3 --retry-backoff-ms 200 --log-format json` | Enable structured runtime logs and transient failure retries for automation pipelines. |
| `./bin/k8doc --strict-check-errors --strict-report-errors` | Fail if any check or optional report section cannot be completed successfully. |
| `./bin/k8doc --timeout 60` | Increase the total timeout for larger clusters. |
| `./bin/k8doc --output json --fail-on warning` | Emit machine-readable JSON and exit non-zero on warning or worse. |
| `./bin/k8doc --write-baseline .k8doc-baseline.json` | Save the current scan as a reusable baseline snapshot. |
| `./bin/k8doc --baseline .k8doc-baseline.json` | Compare the current scan against a saved baseline. |
| `./bin/k8doc --mode incident` | Run the incident-oriented view for active triage. |
| `./bin/k8doc --mode explain --focus-kind namespace --focus payments` | Explain grouped findings for one namespace. |
| `./bin/k8doc --mode dependencies --focus-kind app --focus api` | Trace dependencies for one application. |
| `./bin/k8doc --mode service-view --focus-kind service --focus api` | Inspect one service chain from ingress to backing workloads. |
| `./bin/k8doc --mode node-pool-view` | Summarize findings by node pool. |
| `./bin/k8doc --mode release-readiness --focus-kind namespace --focus prod` | Check release-readiness conditions for a production namespace. |
| `./bin/k8doc --mode multi-cluster-compare --context prod-eu --compare-context prod-us` | Compare findings between two kubeconfig contexts. |
| `./bin/k8doc --mode slo --focus-kind namespace --focus payments` | Show SLO-oriented risk analysis for one namespace. |
| `./bin/k8doc --mode full --report k8doc.html --report-format html` | Generate a full HTML report. |
| `./bin/k8doc --profile pre-upgrade` | Run the pre-upgrade advisory profile. |
| `./bin/k8doc --profile ci --rules ./k8doc-rules.yaml` | Run the CI profile with custom rule overrides. |

## Analysis Modes
- `scan`: standard health summary plus issue table
- `incident`: short critical-path diagnosis with noisy informational findings removed
- `explain`: grouped root-cause style explanations built from findings
- `diff`: compare the current run against a saved baseline
- `timeline`: recent cluster event timeline ordered by newest first
- `dependencies`: ingress/service/pod/PVC/secret/configmap dependency edges
- `service-view`: inspect a concrete service chain from ingress to service, endpoints, pods, PVCs, secrets, and configmaps
- `node-pool-view`: aggregate findings by node pool label (EKS/GKE/AKS/kubeadm-style pools)
- `network-path`: DNS -> ingress/service -> endpoints style path view
- `storage-path`: PVC -> StorageClass -> PV -> VolumeAttachment -> node path view
- `release-readiness`: deployment gate view for quota, PDB, image pull secrets, webhooks, ingress TLS, HPA, and storage
- `upgrade-readiness`: advisory view for node drains, PDBs, webhooks, and single-replica workloads
- `security`: security posture summary including webhook/cert findings, privileged pods, hostPath usage, and default service accounts
- `cost`: waste-oriented view for scaled-zero workloads, orphaned volumes, and idle load balancers
- `slo`: service-oriented availability risk view with a simple blast-radius estimate
- `remediation`: actionable `kubectl` commands for the current findings
- `multi-cluster-compare`: compare current findings and score against another kubeconfig context
- `full`: render all analysis sections together

## Flags
| Flag | Description |
|---|---|
| `--kubeconfig` | Path to kubeconfig. Defaults to `$KUBECONFIG` or `~/.kube/config`. |
| `--context` | Kubeconfig context to use. |
| `--namespace` | Limit checks to one namespace. Empty means all namespaces. |
| `--checks` | Comma-separated checks to run. Default: `pods,gpu,runtimebehavior,podsecurity,secrets,configexposure,networksecurity,storagesecurity,multitenancy,managedk8s,observability,policy,nodes,events,controllers,apiserver,rbac,serviceaccounts,webhooks,cni,controlplane,dns,storage,certificates,quotas,ingress,autoscaling,pdb,scheduling,trends`. |
| `--timeout` | Overall timeout in seconds for all checks. Default: `30`. |
| `--output` | Output format: `table` or `json`. Default: `table`. |
| `--mode` | Analysis mode to render. Default: `scan`. |
| `--focus-kind` | Focus type: `namespace`, `app`, `node`, `service`, or `node-pool`. |
| `--focus` | Focus value used to narrow findings and analysis views. |
| `--profile` | Preset bundle such as `quick`, `prod`, `pre-upgrade`, `network`, `storage`, `admission`, `cost`, or `ci`. |
| `--fail-on` | Exit with code `2` if any finding reaches `info`, `warning`, or `critical`. |
| `--baseline` | Path to a saved JSON baseline used for diff mode. |
| `--write-baseline` | Path to write the current scan as a new baseline. |
| `--timeline-limit` | Maximum number of timeline entries to include. |
| `--rules` | Path to a YAML or JSON rules file for suppression and severity overrides. |
| `--suppress-noise` | Suppress built-in low-signal informational findings. |
| `--strict-check-errors` | Fail the run if any individual check returns an execution error instead of degrading to partial results. |
| `--strict-report-errors` | Fail the run if optional report sections such as timeline, dependencies, compare, or report rendering cannot be generated. |
| `--enable-active-probes` | Enable active Kubernetes API-proxy probes such as DNS, webhook, and control-plane endpoint checks. Disabled by default. |
| `--enable-host-network-probes` | Enable direct host-network probes such as registry reachability, ingress TLS handshakes, and node management port checks. Disabled by default. |
| `--probe-target-classes` | Optional comma-separated allowlist for active probe classes, for example `ingress,registry,node,dns,webhook,controlplane`. Empty means any class enabled by the selected probe mode. |
| `--tls-probe-mode` | TLS probe mode: `handshake-only` or `verify`. Default: `handshake-only`. |
| `--list-chunk-size` | Maximum number of objects fetched per Kubernetes LIST page. Default: `250`. |
| `--max-list-items` | Guardrail for maximum cached items per resource collection. Default: `50000`. |
| `--max-concurrent-checks` | Maximum number of checks executed concurrently. Default: `4`. |
| `--max-concurrent-requests` | Maximum number of concurrent Kubernetes API requests. Default: `8`. |
| `--retry-attempts` | Retry budget for transient API and probe failures. Default: `3`. |
| `--retry-backoff-ms` | Initial retry backoff in milliseconds for transient failures. Default: `200`. |
| `--slow-operation-threshold-ms` | Marks checks and sections as slow when they exceed this duration. Default: `1500`. |
| `--log-format` | Runtime log format: `off`, `text`, or `json`. Default: `off`. |
| `--compare-context` | Secondary kubeconfig context for `multi-cluster-compare`. |
| `--compare-kubeconfig` | Optional kubeconfig file for the comparison context. |
| `--report` | Output path for a generated report. |
| `--report-format` | Report format: `markdown` or `html`. |

## Profiles
- `quick`: fast triage with pods, nodes, events, and apiserver only
- `prod`: full scan with `--fail-on critical`
- `pre-upgrade`: full scan rendered as upgrade readiness advice
- `incident`: critical-path checks including GPU diagnostics rendered as incident mode with `--fail-on warning`
- `release`: deployment-focused checks rendered as release readiness advice
- `network`: network-focused checks rendered as network path analysis
- `storage`: storage-focused checks rendered as storage path analysis
- `admission`: webhook/certificate/apiserver checks rendered as security posture
- `cost`: cost-focused checks rendered as waste analysis
- `ci`: full JSON report with `--fail-on warning`

## GPU Notes
- The built-in `gpu` check is aimed at modern Kubernetes clusters running AI or inference workloads on NVIDIA-backed nodes.
- It inspects node inventory, DaemonSet/operator availability, pod GPU resource declarations, scheduler warning events, runtime mismatch signals, and basic observability coverage.
- It understands both full GPU resources such as `nvidia.com/gpu` and MIG-style resources such as `nvidia.com/mig-*`.

## Execution Model
- Checks run in best-effort mode by default. One failing check does not abort the entire scan.
- Per-check execution results are tracked as `ok`, `finding`, `skipped`, `error`, `not-applicable`, or `partial`.
- Namespace-incompatible checks may report `not-applicable` instead of silently disappearing. For example, the observability scan currently requires all-namespaces scope.
- The execution summary also includes a `traceId`, lightweight runtime stats, slow-check markers, API call counts, and an RBAC/capability preflight summary.
- `partial` means the check or section returned some usable output but lost fidelity because one or more underlying operations failed.
- `skipped` means RBAC or probe policy blocked the check entirely.
- Use `--strict-check-errors` when you want old-style fail-fast behavior for automation.
- Use `--strict-report-errors` when optional analysis and rendering sections must be treated as required.

## Large Cluster Operation
- `k8doc` now pages high-cardinality LIST calls instead of relying on single unbounded cluster-wide fetches.
- Shared runtime caches reuse Pods, Events, Services, Secrets, Roles, and other inventories across checks to reduce API fan-out.
- Use `--list-chunk-size`, `--max-list-items`, `--max-concurrent-checks`, and `--max-concurrent-requests` to tune memory pressure and API load for larger clusters.
- Transient API and probe failures are retried with `--retry-attempts` and `--retry-backoff-ms`.
- Slow operations are surfaced in execution metadata using `--slow-operation-threshold-ms`.
- Synthetic scale tests and runtime benchmarks for these guardrails live in `internal/diagnostics/runtime_scale_test.go` and `internal/diagnostics/runtime_bench_test.go`.

## Probe Safety
- Active probes are off by default.
- `--enable-active-probes` enables API-proxy based probes such as webhook, DNS, and control-plane endpoint checks.
- `--enable-host-network-probes` enables direct network probes from the host running `k8doc`, such as registry TCP reachability, ingress TLS handshakes, and node management port checks.
- `--probe-target-classes` lets you narrow enabled probes to explicit classes instead of allowing every probe in the selected family.
- `--tls-probe-mode handshake-only` measures connectivity and negotiated TLS behavior without requiring trust validation.
- `--tls-probe-mode verify` performs normal TLS verification so certificate chain and hostname mismatches surface as probe failures.

## Rules
Rules can be provided as YAML or JSON and are applied after the checks run. Each rule can match on category, check, kind, namespace, name, severity, or `summaryContains`, then suppress the issue or modify severity/recommendation metadata. Supported actions are `suppress`, `setSeverity`, `addRecommendation`, `addReference`, and `appendSummarySuffix`.

Rules are applied in file order. A matching suppression rule stops further processing for that issue. Ready-to-use examples are available in `./rules/`.

Example:
```yaml
rules:
  - name: prod-quota-escalation
    match:
      namespace: prod
      check: resource-quota
      severity: warning
    setSeverity: critical
    addRecommendation: "Treat quota pressure in prod as release-blocking."
```

## Output
- Results are printed as a table with severity, object, summary, and recommendation. Additional references show on the next indented line when present.
- Severity ordering is critical → warning → info.
- A health summary is shown first with an overall score plus category scores.
- JSON output includes a versioned contract with `schemaVersion`, findings, grouped summary, execution metadata, optional diff details, analysis sections, focus metadata, applied rule names, probe policy, and optional cluster comparison data.
- The published schema for the current contract is in `./schema/k8doc-report-v1alpha2.schema.json`, with compatibility notes in `./schema/README.md`.
- Individual findings may include `detection` and `confidence` metadata, especially for policy-gated and active-probe based results.
- Execution metadata records per-check and per-section status, duration, issue count, and machine-readable error codes such as RBAC denial, timeout, or not-applicable scope.
- Markdown/HTML reports can be generated for incident reviews or health snapshots.
- The CI gate for the output contract and runtime regression tests is defined in `./.github/workflows/quality-gates.yml`.

## RBAC
- RBAC profiles are documented in `./deploy/rbac/README.md`.
- `./deploy/rbac/k8doc-reader.yaml` is the minimal read-only cluster profile.
- `./deploy/rbac/k8doc-namespace-reader.yaml` is the namespace-only profile for tenant or app-team scoped runs.
- `./deploy/rbac/k8doc-cluster-reader.yaml` is the broader cluster-wide profile for full posture and control-plane visibility.
- The scanner performs a lightweight capability preflight using `SelfSubjectAccessReview` and reports denied capabilities in execution metadata instead of silently failing.
- Namespace-only RBAC degrades `gpu`, `nodes`, `managedk8s`, `apiserver`, `controlplane`, `controlplane-security`, `webhooks`, and cluster-scope portions of `rbac`, `multitenancy`, `serviceaccounts`, `storage-security`, and `observability`.

## Signal Policy
- Severity, detection source, and confidence are normalized before reports are emitted.
- The policy is documented in `./docs/signal-policy.md`.
- Test enforcement lives in `ValidateIssuePolicy` and `ValidateIssuesPolicy`, with consistency checks across representative issue sources in `internal/diagnostics/types_test.go`.

## Operations
- CI and in-cluster runbooks are documented in `./docs/operations.md`.
- For CI, prefer `--output json`, `--strict-check-errors`, and `--strict-report-errors` so contract changes and degraded sections fail loudly.
- For in-cluster runs, start with one of the RBAC profiles in `deploy/rbac/` and keep probes disabled unless the runner has the right network reachability.

## Notes
- Requires Go and network access to the Kubernetes API. Run `go mod tidy` once to download dependencies.
- Some reachability probes, such as registry and ingress TLS checks, are executed from the host running `k8doc`, not from inside the cluster network; these remain disabled unless explicitly enabled.
- If no issues are found, the tool reports a healthy cluster based on the inspected signals.
