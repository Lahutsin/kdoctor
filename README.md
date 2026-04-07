# kdoctor

Version: 0.0.2.1-beta

Minimal Kubernetes troubleshooter written in Go. It connects to your cluster, runs a bundle of quick health checks, and prints a compact table of findings with recommendations.

Beyond the base scan, `kdoctor` can now explain grouped findings, diff against a baseline, build event timelines, focus on a namespace/app/node, trace dependency paths, evaluate upgrade/security/cost posture, apply custom rules, and emit shareable reports.

It also supports an incident-focused view, service-chain inspection, node-pool diagnostics, release readiness checks, SLO risk estimation with blast radius hints, built-in noise suppression, and multi-cluster comparison across kubeconfig contexts.

## Checks
- Pods: scheduling failures, image pull errors, crash loops, OOM kills, repeated restarts
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

## Usage
```bash
go run ./cmd/kdoctor \
  --kubeconfig ~/.kube/config \
  --context my-cluster \
  --namespace default
```

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
- `--kubeconfig` (string): path to kubeconfig; defaults to `$KUBECONFIG` or `~/.kube/config`
- `--context` (string): kubeconfig context to use
- `--namespace` (string): limit checks to a namespace (empty scans all namespaces)
- `--checks` (string): comma-separated checks to run; defaults to `pods,runtimebehavior,podsecurity,secrets,configexposure,networksecurity,storagesecurity,multitenancy,managedk8s,observability,policy,nodes,events,controllers,apiserver,rbac,serviceaccounts,webhooks,cni,controlplane,dns,storage,certificates,quotas,ingress,autoscaling,pdb,scheduling,trends`
- `--timeout` (int): overall timeout in seconds for all checks (default 30)
- `--output` (string): `table` or `json` output (default `table`)
- `--mode` (string): analysis mode to render; defaults to `scan`
- `--focus-kind` (string): `namespace`, `app`, `node`, `service`, or `node-pool`
- `--focus` (string): the focus value used to filter issues and narrow path/dependency views
- `--profile` (string): preset bundles such as `quick`, `prod`, `pre-upgrade`, `network`, `storage`, `admission`, `cost`, `ci`
- `--fail-on` (string): exit with code `2` if any issue reaches `info`, `warning`, or `critical`
- `--baseline` (string): path to a saved JSON scan for diffing new vs resolved findings
- `--write-baseline` (string): path to write the current scan as a reusable JSON baseline
- `--timeline-limit` (int): max number of timeline events to return
- `--rules` (string): path to a YAML/JSON rules file for suppression, severity overrides, and recommendation augmentation
- `--suppress-noise` (bool): suppress built-in non-actionable informational findings such as intentional scaled-zero workloads
- `--compare-context` (string): second kubeconfig context used by `multi-cluster-compare`
- `--compare-kubeconfig` (string): optional kubeconfig path for the comparison context
- `--report` (string): output path for a rendered markdown/html report
- `--report-format` (string): `markdown` or `html` report output

## Profiles
- `quick`: fast triage with pods, nodes, events, and apiserver only
- `prod`: full scan with `--fail-on critical`
- `pre-upgrade`: full scan rendered as upgrade readiness advice
- `incident`: critical-path checks rendered as incident mode with `--fail-on warning`
- `release`: deployment-focused checks rendered as release readiness advice
- `network`: network-focused checks rendered as network path analysis
- `storage`: storage-focused checks rendered as storage path analysis
- `admission`: webhook/certificate/apiserver checks rendered as security posture
- `cost`: cost-focused checks rendered as waste analysis
- `ci`: full JSON report with `--fail-on warning`

## Rules
Rules can be provided as YAML or JSON and are applied after the checks run. Each rule can match on category, check, kind, namespace, name, severity, or `summaryContains`, then suppress the issue or modify severity/recommendation metadata.

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

Examples:
- Run only pod and node checks: `go run ./cmd/kdoctor --checks pods,nodes`
- Extend the timeout for large clusters: `go run ./cmd/kdoctor --timeout 60`
- Emit machine-readable output for CI: `go run ./cmd/kdoctor --output json --fail-on warning`
- Save a baseline and compare later: `go run ./cmd/kdoctor --write-baseline .kdoctor-baseline.json` then `go run ./cmd/kdoctor --baseline .kdoctor-baseline.json`
- Run incident mode during an outage: `go run ./cmd/kdoctor --mode incident`
- Explain grouped findings for a namespace: `go run ./cmd/kdoctor --mode explain --focus-kind namespace --focus payments`
- Trace dependencies for an app: `go run ./cmd/kdoctor --mode dependencies --focus-kind app --focus api`
- Inspect one service chain: `go run ./cmd/kdoctor --mode service-view --focus-kind service --focus api`
- Inspect node pools: `go run ./cmd/kdoctor --mode node-pool-view`
- Run deployment readiness checks: `go run ./cmd/kdoctor --mode release-readiness --focus-kind namespace --focus prod`
- Compare two contexts: `go run ./cmd/kdoctor --mode multi-cluster-compare --context prod-eu --compare-context prod-us`
- Show SLO-oriented service risks: `go run ./cmd/kdoctor --mode slo --focus-kind namespace --focus payments`
- Render a full HTML report: `go run ./cmd/kdoctor --mode full --report kdoctor.html --report-format html`
- Run a pre-upgrade audit: `go run ./cmd/kdoctor --profile pre-upgrade`
- Apply custom rules during a CI scan: `go run ./cmd/kdoctor --profile ci --rules ./kdoctor-rules.yaml`

## Output
- Results are printed as a table with severity, object, summary, and recommendation. Additional references show on the next indented line when present.
- Severity ordering is critical → warning → info.
- A health summary is shown first with an overall score plus category scores.
- JSON output includes findings, grouped summary, optional diff details, analysis sections, focus metadata, applied rule names, and optional cluster comparison data.
- Markdown/HTML reports can be generated for incident reviews or health snapshots.

## Notes
- Requires Go and network access to the Kubernetes API. Run `go mod tidy` once to download dependencies.
- Some reachability probes, such as registry and ingress TLS checks, are executed from the host running `kdoctor`, not from inside the cluster network.
- If no issues are found, the tool reports a healthy cluster based on the inspected signals.
