# Triage and response runbook

What to do when each detection in this repo fires. Each entry has what the alert means, how
to triage it, and how to respond. Queries use the field names from the BOTS v3 data in this
lab. Replace `index=botsv3` with your own index in production.

Priority order when several fire on one host: encoded PowerShell and the fodhelper bypass
first (active implant and privilege escalation), then Temp execution, then the cloud alerts.

## win_powershell_encoded_hidden

Encoded, hidden PowerShell. Usually a staged implant, not administration.

Triage:
- Decode the payload. Copy the base64 after `-enc` and decode it (it is UTF-16LE), then read
  what it does.
- Pull the parent chain and the host:
  ```spl
  index=botsv3 sourcetype=XmlWinEventLog EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
  | table _time host User ParentImage ParentCommandLine CommandLine | sort _time
  ```
- Check outbound connections from that PowerShell for a C2 address:
  ```spl
  index=botsv3 sourcetype=XmlWinEventLog EventCode=3 Image="*powershell.exe" host=<host>
  | stats count by DestinationIp DestinationPort | sort - count
  ```

Response:
- Isolate the host from the network. Do not shut it down (you lose memory).
- Kill the PowerShell process and any child processes.
- Hunt for persistence (see the fodhelper and registry notes below) and scope how many hosts
  show the same pattern before closing.

False positives: rare automation that base64-encodes commands. Confirm against your baseline
of who runs encoded PowerShell.

## win_fodhelper_uac_bypass

fodhelper.exe spawning a shell. A UAC bypass that runs code at high integrity.

Triage:
- Read the child command line. In this lab it reads a payload from a fake registry value:
  ```spl
  index=botsv3 sourcetype=XmlWinEventLog EventCode=1 ParentImage="*fodhelper.exe"
  | table _time host User Image CommandLine | sort _time
  ```
- Look for the registry persistence the implant uses, for example a value under
  `HKCU\Software\Microsoft\Windows Update`.

Response:
- Treat the host as compromised at high integrity. Isolate it.
- Remove the fodhelper-related registry keys
  (`HKCU\Software\Classes\ms-settings\shell\open\command`) and the fake payload value.
- Continue the implant investigation, because UAC bypass is a step, not the whole intrusion.

False positives: very rare. fodhelper normally opens the Optional Features page, not a shell.

## win_exec_from_windows_temp

A process image running from a Windows Temp path. Attacker tooling is often staged there.

Triage:
- Identify the binary, its parent, and its network connections:
  ```spl
  index=botsv3 sourcetype=XmlWinEventLog EventCode=1 Image="*\\Temp\\*"
  | table _time host User ParentImage Image CommandLine | sort _time
  ```
- If the binary makes many internal connections, it may be a scanner (in this lab,
  `hdoor.exe`). If it posts to an internal web app, it may be an exploit client
  (`iexeplorer.exe`).

Response:
- Isolate the host, capture the binary for analysis, then remove it.
- Check the parent process and persistence.

False positives: installers and updaters stage executables in Temp. The rule already filters
DismHost and common updaters; add others from your own baseline.

## aws_s3_bucket_made_public

A PutBucketAcl or PutBucketPolicy that grants access to AllUsers or AuthenticatedUsers.

Triage:
- Identify who did it, which bucket, and whether it was reverted:
  ```spl
  index=botsv3 sourcetype=aws:cloudtrail (eventName=PutBucketAcl OR eventName=PutBucketPolicy)
  | table _time userIdentity.userName requestParameters.bucketName sourceIPAddress userAgent | sort _time
  ```
- Determine what the bucket holds and whether anything was read while it was public.

Response:
- Revert the ACL to private immediately.
- Review the acting identity for compromise, and rotate its credentials if in doubt.

False positives: buckets intentionally made public (static sites, public datasets). Confirm
with the owner.

## aws_iam_access_key_created

A new IAM access key. Attackers mint keys to keep programmatic access.

Triage:
- Who created it, for which user, from which IP, and is the creator an approved admin:
  ```spl
  index=botsv3 sourcetype=aws:cloudtrail eventName=CreateAccessKey
  | table _time userIdentity.userName responseElements.accessKey.userName sourceIPAddress userAgent | sort _time
  ```

Response:
- If unauthorized, disable then delete the key, and review the target user's recent activity.

False positives: routine key rotation by admins or CI/CD. Baseline who normally creates keys.

## aws_iam_user_created

A new IAM user, a common persistence foothold.

Triage:
- Who created it, the new user name, and the source IP:
  ```spl
  index=botsv3 sourcetype=aws:cloudtrail eventName=CreateUser
  | table _time userIdentity.userName requestParameters.userName sourceIPAddress userAgent | sort _time
  ```

Response:
- If unauthorized, delete the user and any keys or policies attached to it, then review the
  creating identity.

False positives: legitimate onboarding by admins. Baseline your normal IAM admins.
