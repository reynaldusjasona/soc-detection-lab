# Intrusion overview

How the three investigations fit into one operation against Frothly on 2018-08-20. Endpoint
evidence is Sysmon, cloud evidence is AWS CloudTrail.

```mermaid
flowchart TD
    A["Initial access, browser context<br/>2018-08-20 ~09:59 to 10:01"] --> B["PowerShell Empire implant<br/>encoded, hidden PowerShell"]
    B --> H1["BSTOLL-L<br/>user BudStoll"]
    B --> H2["ABUNGST-L<br/>user AlBungstein"]
    B --> H3["FYODOR-L<br/>user FyodorMalteskesko"]
    H3 --> P["Privilege escalation<br/>fodhelper UAC bypass to SYSTEM"]
    H3 --> PER["Persistence<br/>registry, scheduled task, WMI"]
    H3 --> C2["C2 beacon<br/>45.77.53.176"]
    H3 --> S["Struts2 exploit client<br/>iexeplorer.exe"]
    S --> SRV["Inventory server<br/>192.168.9.30:8080"]
    SRV --> R["useradd UID 0, drop and compile exploit,<br/>reverse shell to 45.77.53.176:8088"]
    H3 --> SCAN["Internal scan<br/>hdoor.exe 192.168.9.0/24"]
    H1 --> CLOUD["AWS console as bstoll"]
    CLOUD --> S3["frothlywebcode S3 bucket made public<br/>2018-08-20 13:01, reverted 13:57"]
```

- Investigation 1 covers the cloud side (`bstoll`, IAM, the public S3 bucket).
- Investigation 2 covers the endpoint side on FYODOR-L (implant, Struts2, C2, scanning).
- Investigation 3 correlates the implant across BSTOLL-L, ABUNGST-L, and FYODOR-L and ties
  the endpoint and cloud sides through the `bstoll` / BudStoll identity.
