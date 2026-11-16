# Investigations

Incident investigation writeups built from public datasets.

## Dataset

Splunk Boss of the SOC (BOTS) v3. Open license (CC0). Pre-indexed Splunk data with an official question-and-answer key.

## Method

Work the BOTS questions in Splunk, document the SPL queries used and the reasoning, then check each answer against the official key.

## Files

One Markdown writeup per investigation. Each covers: scenario, questions answered, queries used, findings, and which answers matched the key.

- `01-aws-account-compromise.md` - cloud side: AWS CloudTrail, IAM persistence, public S3 bucket.
- `02-fyodor-struts-compromise.md` - endpoint side: Empire implant on FYODOR-L, Struts2 attack on an internal server, C2 and internal scanning.
