# Investigations

Incident investigation writeups built from public datasets.

## Dataset

Splunk Boss of the SOC (BOTS) v3. Open license (CC0). Pre-indexed Splunk data covering one full intrusion.

## Method

Investigate the data in Splunk by following the evidence, and document each question asked, the SPL query used, and the finding.

## Files

One Markdown writeup per investigation. Each covers: scenario, questions answered, queries used, findings, ATT&CK techniques, and detection ideas.

- `01-aws-account-compromise.md` - cloud side: AWS CloudTrail, IAM persistence, public S3 bucket.
- `02-fyodor-struts-compromise.md` - endpoint side: Empire implant on FYODOR-L, Struts2 attack on an internal server, C2 and internal scanning.
- `03-campaign-correlation.md` - correlation: the implant across BSTOLL-L, ABUNGST-L and FYODOR-L, and the link to the cloud intrusion through the bstoll identity.
