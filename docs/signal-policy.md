# Signal Policy

## Severity

- `critical`: likely production-impacting or security-significant condition requiring immediate action.
- `warning`: actionable drift or risk with moderate confidence.
- `info`: advisory, policy, or low-confidence signal.

## Detection

- `direct`: derived from explicit API state or manifest facts.
- `policy`: emitted because a configured probe or capability policy blocked normal execution.
- `active-probe`: emitted from a live probe against an endpoint or proxied target.
- `heuristic`: inferred from logs, metadata, events, labels, or behavioral patterns.
- `derived`: synthesized default when no stronger detection source is available.

## Confidence

- `high`: direct evidence or policy-controlled signal.
- `medium`: strong heuristic or active probe with some environmental ambiguity.
- `low`: weak heuristic or advisory signal.

## Enforcement

- The code normalizes missing `category`, `detection`, and `confidence` fields.
- `ValidateIssuePolicy` and `ValidateIssuesPolicy` enforce allowed values and required fields in tests.