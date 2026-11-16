# soc-detection-lab

![validate-detections](https://github.com/reynaldusjasona/soc-detection-lab/actions/workflows/ci.yml/badge.svg)

Detection engineering portfolio project. Build a small lab, run attacks against it, catch them with my own detection rules, and check the rules against external ground truth.

Target role: SOC analyst, working toward detection engineer.

## Status

Started October 2026.

- Investigation 1 (AWS account compromise, BOTS v3) written up, answers checked against the official key.
- 3 Sigma rules derived from it, validated against the BOTS v3 data.
- Detection-as-code pipeline live: pySigma validation and the ATT&CK coverage map run in CI on every push.

Next: more BOTS v3 investigations (host and endpoint side), then the home lab.

## Structure

- `investigations/` — incident investigation writeups (BOTS v3)
- `detections/` — Sigma detection rules
- `coverage/` — MITRE ATT&CK coverage map (Navigator layer, generated)
- `tools/` — rule validation and layer generation scripts
- `docs/` — lab setup and architecture notes

## Validation

```bash
pip install -r requirements.txt
python tools/validate_rules.py          # structural checks + pySigma conversion to SPL
python tools/generate_navigator_layer.py # rebuild coverage/attack-navigator-layer.json
```

Both run in CI (`.github/workflows/ci.yml`). CI also fails if the committed coverage layer is out of date.

## Roadmap

1. Investigation writeups from BOTS v3, answers checked against the official key. *(1 of several done)*
2. Home lab: Active Directory, Sysmon, logs shipped into a SIEM
3. Sigma rules, validated with Atomic Red Team and a normal-activity baseline
4. ATT&CK coverage map and a detection-as-code CI pipeline. *(done)*
5. One upstream contribution (SigmaHQ PR) and full documentation

## Tools

Splunk, Elastic or Wazuh, Sysmon, Atomic Red Team, MITRE Caldera, Sigma, pySigma, MITRE ATT&CK Navigator.
