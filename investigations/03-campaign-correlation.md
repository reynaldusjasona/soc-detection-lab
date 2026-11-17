# Investigation 3 - One campaign across three laptops, and the link to the cloud

Dataset: Splunk BOTS v3. This writeup does not open a new data source. It correlates the
endpoint findings from investigation 2 across hosts, and ties the endpoint intrusion to the
AWS intrusion in investigation 1. The point is the pivot: the same operation runs on the
laptops and in the cloud.

Set the time range to **All time**.

## Summary

The same encoded, hidden PowerShell implant (PowerShell Empire) runs on three Frothly
laptops on 2018-08-20, with first execution on each within about two minutes:

| Host | User | Implant first seen (UTC) | Implant last seen (UTC) |
|---|---|---|---|
| BSTOLL-L | AzureAD\BudStoll | 09:59:48 | 11:28:40 |
| ABUNGST-L | AzureAD\AlBungstein | 10:00:54 | 10:00:59 |
| FYODOR-L | AzureAD\FyodorMalteskesko, NT AUTHORITY\SYSTEM | 10:01:41 | 11:32:13 |

Three users hit inside two minutes points to one delivery, not three unrelated events.
On FYODOR-L the implant also runs as `NT AUTHORITY\SYSTEM`, so privilege escalation
succeeded there (the fodhelper UAC bypass from investigation 2). FYODOR-L is the host the
operator worked from: the Struts2 attack, the internal scan, and the main C2 beacon all run
there (investigation 2).

The link to the cloud is **BSTOLL-L**. That is BudStoll's laptop, and `bstoll` is the AWS
identity that made the `frothlywebcode` S3 bucket public at 13:01:46 the same day
(investigation 1). So the identity whose laptop carries the implant is the same identity
that performs the cloud exposure, on the same day, within the implant's active window.

## Questions

### Q1. How far has the implant spread, and to which users?

```spl
index=botsv3 sourcetype=XmlWinEventLog EventCode=1 Image="*powershell.exe"
  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
  (CommandLine="*-W Hidden*" OR CommandLine="*-NonI*" OR CommandLine="*-NoP*")
| stats count min(_time) as first max(_time) as last values(User) as users by host
| sort - count
```

Finding: three hosts, three users (BudStoll, AlBungstein, FyodorMalteskesko), all on
2018-08-20. First executions land within two minutes of each other (09:59:48, 10:00:54,
10:01:41), consistent with a single delivery across several recipients. FYODOR-L shows the
most activity and runs the implant as both the user and `SYSTEM`.

### Q2. Which host did the operator work from, and what did they reach?

From investigation 2, FYODOR-L is the active host: it runs the Struts2 exploit client
against `192.168.9.30`, scans the internal subnet with `hdoor.exe`, and beacons to
`45.77.53.176`. ABUNGST-L and BSTOLL-L show the implant but not the follow-on tooling in
this data, so they read as additional footholds rather than the working host.

### Q3. How does the endpoint intrusion connect to the cloud intrusion?

The connecting identity is `bstoll` / BudStoll. In investigation 1, `bstoll` operates in the
AWS console and makes `frothlywebcode` public at 13:01:46 on 2018-08-20. In this
investigation, BudStoll's laptop (BSTOLL-L) carries the Empire implant from 09:59:48 the same
morning, with implant activity continuing to 11:28:40. The endpoint compromise is in place
before the cloud exposure action, and the two windows overlap.

Whether the cloud actions ran from the compromised laptop, from stolen credentials, or from a
compromised AWS session cannot be settled from these logs alone. That needs the browser and
authentication logs tied to the console session. What the data does establish is that the
endpoint intrusion and the cloud intrusion share an identity and a day, so they are one
operation rather than two.

## ATT&CK techniques

Adds to the techniques already recorded in investigations 1 and 2:

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing (assessed, not confirmed) | T1566 | Implant lands on three users within two minutes; delivery vector not in this data |
| Defense Evasion / Privilege Escalation | Valid Accounts | T1078 | `bstoll` identity used across the compromised endpoint and the AWS console |

## Detection ideas

The single-host rules from investigation 2 already fire on this activity. The campaign shape
suggests one more, left for later because it needs correlation logic rather than a single
event: the same implant pattern (encoded, hidden PowerShell) seen on several hosts within a
short window. That is a Sigma correlation rule or a scheduled search with a host-count
threshold, a good fit once the detection pipeline grows.
