# Detections

Sigma detection rules written and tested against lab telemetry.

## Validation

Each rule is checked two ways:

- It fires when the matching Atomic Red Team test runs.
- It stays silent on a baseline of normal activity. The false-positive rate is recorded.

Rules are tested with pySigma in CI before merge.
