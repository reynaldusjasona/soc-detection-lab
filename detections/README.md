# Detections

Sigma rules written from the behaviours found in the investigations in this repo, then
validated against the same data before being kept.

## How each rule is validated

1. **Lineage.** Every rule links back to the investigation that motivated it (see the
   `references` field). Detections here come from observed attacker behaviour, not from a
   generic list.
2. **True positive.** The rule's logic is converted to SPL and run against the BOTS v3
   data. It must catch the real incident event(s) it was written for.
3. **Precision.** The same search must not fire on the benign look-alike activity in the
   dataset (for example, an ACL change that *removes* a public grant).
4. **Compilation.** Rules are checked with `pySigma` so they parse and convert cleanly.
   This runs in CI once the pipeline is added.

A baseline of normal activity and Atomic Red Team coverage comes later, with the home lab.

## Rules

| Rule | Tactic | ATT&CK | Source investigation |
|---|---|---|---|
| `aws_s3_bucket_made_public.yml` | Collection | T1530 | 01 — AWS account compromise |
| `aws_iam_access_key_created.yml` | Persistence | T1098.001 | 01 — AWS account compromise |
| `aws_iam_user_created.yml` | Persistence | T1136.003 | 01 — AWS account compromise |
