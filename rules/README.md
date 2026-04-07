# Rules Examples

This directory contains example rule files for every rule capability currently supported by `kdoctor`.

Supported match fields:
- `category`
- `check`
- `kind`
- `namespace`
- `name`
- `severity`
- `summaryContains`

Supported actions:
- `suppress`
- `setSeverity`
- `addRecommendation`
- `addReference`
- `appendSummarySuffix`

Behavior notes:
- Rules are applied in order.
- Exact-match fields are case-sensitive because they are compared directly to the emitted finding fields.
- `summaryContains` is a case-insensitive substring match.
- If `suppress: true` matches, the issue is removed and later rules are not applied to it.

Example usage:

```bash
./dist/kdoctor --rules ./rules/01-all-match-fields.yaml
./dist/kdoctor --rules ./rules/06-json-rules.json --output json
```