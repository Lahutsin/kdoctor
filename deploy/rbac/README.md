# RBAC Profiles

`k8doc` ships with three RBAC profiles for different operating models.

- `k8doc-reader.yaml`: minimal read-only cluster profile with SAR preflight support.
- `k8doc-namespace-reader.yaml`: namespace-only profile for tenant-scoped or app-scoped scans.
- `k8doc-cluster-reader.yaml`: broader cluster-wide read-only profile for full posture and control-plane visibility.

## Degraded Checks Under Reduced Rights

- Namespace-only RBAC degrades `gpu`, `nodes`, `managedk8s`, `apiserver`, `controlplane`, `controlplane-security`, `webhooks`, and cluster-scope portions of `rbac`, `multitenancy`, `serviceaccounts`, `storage-security`, and `observability`.
- Minimal read-only RBAC keeps most passive checks available but active probe dependent findings still require explicit probe flags.
- Any denied capability is surfaced in execution preflight and individual check records as `skipped` or `partial` instead of silently disappearing.

## Usage Notes

- Update the namespace fields in `k8doc-namespace-reader.yaml` before applying it.
- Prefer namespace-only for tenant self-service, minimal read-only for shared platform diagnostics, and cluster-reader for full cluster posture scans.