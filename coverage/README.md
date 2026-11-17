# Coverage

MITRE ATT&CK coverage map for the detection rules in this repo.

`attack-navigator-layer.json` is an ATT&CK Navigator layer, generated from the rules in
`detections/` by `tools/generate_navigator_layer.py`. It is a build artifact: regenerate
it after changing rules. CI fails if the committed layer is out of date.

```bash
python tools/generate_navigator_layer.py
```

## Viewing it

Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose
"Open Existing Layer" then "Upload from local", and select `attack-navigator-layer.json`.
Each covered technique is scored by how many rules detect it.

## Current coverage

| Technique | ID | Tactic | Rules |
|---|---|---|---|
| Account Manipulation: Additional Cloud Credentials | T1098.001 | Persistence | 1 |
| Create Account: Cloud Account | T1136.003 | Persistence | 1 |
| Data from Cloud Storage | T1530 | Collection | 1 |
| Command and Scripting Interpreter | T1059 | Execution | 1 |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution | 1 |
| Abuse Elevation Control Mechanism: Bypass User Account Control | T1548.002 | Privilege Escalation | 1 |

The first three come from investigation 01 (AWS account compromise), the last three from
investigation 02 (FYODOR-L Struts2 compromise).
