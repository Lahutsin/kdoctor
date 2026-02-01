# kdoctor

Version: 0.0.1-beta

Minimal Kubernetes troubleshooter written in Go. It connects to your cluster, runs a bundle of quick health checks, and prints a compact table of findings with recommendations.

## Checks
- Pods: scheduling failures, image pull errors, crash loops, OOM kills, repeated restarts
- Nodes: NotReady, memory/disk pressure, network unavailable
- Events: recent warning events for fast triage
- Controllers: Deployments/DaemonSets/ReplicaSets/Jobs/CronJobs availability and failures
- API server and etcd: readyz/livez probes, latency, and etcd DB size hints
- Control plane pods: scheduler/controller-manager readiness plus lightweight metrics signals
- Webhooks: service presence/endpoints, caBundle, failurePolicy, timeoutSeconds, and probe latency
- CNI/CSI: health of common CNI daemonsets, CSI daemonsets, and registered CSI drivers

## Usage
```bash
go run ./cmd/kdoctor \
  --kubeconfig ~/.kube/config \
  --context my-cluster \
  --namespace default
```

## Flags
- `--kubeconfig` (string): path to kubeconfig; defaults to `$KUBECONFIG` or `~/.kube/config`
- `--context` (string): kubeconfig context to use
- `--namespace` (string): limit checks to a namespace (empty scans all namespaces)
- `--checks` (string): comma-separated checks to run; defaults to `pods,nodes,events,controllers,apiserver,webhooks,cni,controlplane`
- `--timeout` (int): overall timeout in seconds for all checks (default 30)

Examples:
- Run only pod and node checks: `go run ./cmd/kdoctor --checks pods,nodes`
- Extend the timeout for large clusters: `go run ./cmd/kdoctor --timeout 60`

## Output
- Results are printed as a table with severity, object, summary, and recommendation. Additional references show on the next indented line when present.
- Severity ordering is critical → warning → info.

## Notes
- Requires Go and network access to the Kubernetes API. Run `go mod tidy` once to download dependencies.
- If no issues are found, the tool reports a healthy cluster based on the inspected signals.
