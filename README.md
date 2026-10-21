# soc-detection-lab

Detection engineering portfolio project. Build a small lab, run attacks against it, catch them with my own detection rules, and check the rules against external ground truth.

Target role: SOC analyst, working toward detection engineer.

## Status

Started October 2026. Week 1 in progress: investigation writeups from the Splunk BOTS v3 dataset.

## Structure

- `investigations/` — incident investigation writeups (BOTS v3)
- `detections/` — Sigma detection rules
- `coverage/` — MITRE ATT&CK coverage map
- `docs/` — lab setup and architecture notes

## Roadmap

1. Investigation writeups from BOTS v3, answers checked against the official key
2. Home lab: Active Directory, Sysmon, logs shipped into a SIEM
3. Sigma rules, validated with Atomic Red Team and a normal-activity baseline
4. ATT&CK coverage map and a detection-as-code CI pipeline
5. One upstream contribution (SigmaHQ PR) and full documentation

## Tools

Splunk, Elastic or Wazuh, Sysmon, Atomic Red Team, MITRE Caldera, Sigma, pySigma, MITRE ATT&CK Navigator.
