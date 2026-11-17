# soc-detection-lab

![validate-detections](https://github.com/reynaldusjasona/soc-detection-lab/actions/workflows/ci.yml/badge.svg)

Detection engineering portfolio project. I investigate one intrusion in the Splunk BOTS v3 dataset, write Sigma rules for the attacker behaviour I found, validate each rule against the data, and keep the rules under CI.

Target role: SOC analyst, working toward detection engineer.

## What is in here

- Three investigations that trace one intrusion against Frothly on 2018-08-20, across AWS CloudTrail and Sysmon.
- 6 Sigma rules written from those findings, each run against the dataset to confirm it catches the real event.
- A detection-as-code pipeline: pySigma converts every rule to SPL and the ATT&CK coverage layer is regenerated and checked in CI on every push.
- A runbook with triage and response steps per rule.
- A small Splunk app that extracts Sysmon fields from the BOTS v3 XML events, which the official add-on does not do for this dataset.

## The intrusion

The three investigations are one operation. See [docs/intrusion-overview.md](docs/intrusion-overview.md) for the attack flow diagram.

| # | Writeup | Side | Covers |
|---|---|---|---|
| 1 | [AWS account compromise](investigations/01-aws-account-compromise.md) | Cloud (CloudTrail) | `web_admin` and `bstoll`, failed IAM persistence, a public S3 bucket |
| 2 | [FYODOR-L Struts2 compromise](investigations/02-fyodor-struts-compromise.md) | Endpoint (Sysmon) | Empire implant, Struts2 attack on an internal server, C2, internal scanning |
| 3 | [Campaign correlation](investigations/03-campaign-correlation.md) | Both | The implant on BSTOLL-L, ABUNGST-L and FYODOR-L, and the link to the cloud through the `bstoll` identity |

## Detections and results

Each rule was converted to SPL and run against BOTS v3 (1.9 million events). Counts are the events each rule matched.

| Rule | ATT&CK | Level | Matches in BOTS v3 | Notes |
|---|---|---|---|---|
| [aws_s3_bucket_made_public](detections/aws_s3_bucket_made_public.yml) | T1530 | high | 1 | The `frothlywebcode` exposure. Does not fire on the later call that removed the public grant. |
| [aws_iam_access_key_created](detections/aws_iam_access_key_created.yml) | T1098.001 | medium | 1 | `web_admin` CreateAccessKey attempt (denied). No other matches in the dataset. |
| [aws_iam_user_created](detections/aws_iam_user_created.yml) | T1136.003 | medium | 1 | `web_admin` CreateUser attempt (denied). No other matches in the dataset. |
| [win_powershell_encoded_hidden](detections/win_powershell_encoded_hidden.yml) | T1059.001 | high | 11 | Empire stagers on three laptops. Does not fire on plain PowerShell. |
| [win_fodhelper_uac_bypass](detections/win_fodhelper_uac_bypass.yml) | T1548.002 | high | 2 | Both on FYODOR-L, both the implant. No other matches in the dataset. |
| [win_exec_from_windows_temp](detections/win_exec_from_windows_temp.yml) | T1059 | medium | 35 | 34 `iexeplorer.exe`, 1 `hdoor.exe`. Tuned after it first hit `DismHost.exe` and `DropboxUpdate.exe`. |

The coverage map is in [coverage/](coverage/README.md). Triage and response steps are in [docs/runbook.md](docs/runbook.md).

## Limitations

- The rules are validated against the same dataset they were written from. They have not been tested against an independent attack run or a baseline of normal activity.
- BOTS v3 is one day of data from one environment. False positive rates in a production network are unknown, which is why the two broad rules are `medium`.
- The investigation questions are my own. They follow the evidence rather than the official BOTS v3 question set.

## Structure

- `investigations/`: incident investigation writeups (BOTS v3)
- `detections/`: Sigma detection rules
- `coverage/`: MITRE ATT&CK coverage map (Navigator layer, generated)
- `tools/`: rule validation and layer generation scripts
- `splunk/`: local Splunk app for Sysmon field extraction
- `docs/`: lab architecture, Splunk setup, intrusion overview, runbook

## Run it

Rule validation, no Splunk needed:

```bash
pip install -r requirements.txt
python tools/validate_rules.py           # structural checks + pySigma conversion to SPL
python tools/generate_navigator_layer.py # rebuild coverage/attack-navigator-layer.json
```

Both run in CI (`.github/workflows/ci.yml`). CI fails if the committed coverage layer is out of date.

To reproduce the investigations, follow [docs/splunk-setup.md](docs/splunk-setup.md) (Splunk in Docker with the BOTS v3 dataset).

## Tools

Splunk, Sysmon, AWS CloudTrail, Sigma, pySigma, MITRE ATT&CK Navigator, Docker, GitHub Actions.

## Future work

- A home lab (Active Directory, Sysmon, Atomic Red Team) to test the rules against self-generated attacks and a normal-activity baseline.
- An upstream contribution to SigmaHQ.
