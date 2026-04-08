# Output Compatibility

- The machine-readable report contract is versioned by `schemaVersion`.
- `v1alpha2` is defined by `k8doc-report-v1alpha2.schema.json`.
- Backward-incompatible JSON changes must use a new schema version and publish a new schema file.
- Backward-compatible additions may extend the current schema with optional fields.
- Golden serialization tests must be updated in the same change as any contract change.
- The canonical golden fixture for `v1alpha2` lives in `../cmd/k8doc/testdata/report-v1alpha2.golden.json`.
- CI or release checks should validate both the schema file and the golden fixture before shipping output-contract changes.
- The default CI gate for these checks is `../.github/workflows/quality-gates.yml`.