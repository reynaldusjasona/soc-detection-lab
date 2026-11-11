# Investigation 1 — AWS account compromise

Dataset: Splunk BOTS v3 (`index=botsv3`). Scenario: an attacker operates inside Frothly's AWS environment. This writeup traces the cloud side of the intrusion: who is calling the AWS API, how persistence was established, and what was exposed, using CloudTrail.

Set the time range to **All time** for every search (data is from August 2018).

> Method note: fields come from Splunk's automatic JSON extraction, so they use dot notation (`userIdentity.userName`, `requestParameters.bucketName`). If a field returns nothing, open one raw event and read the exact field name from the left-hand field panel, then adjust the query.

## Summary

The cloud intrusion runs through two identities: the IAM user `web_admin`, operated from several external IPs with scripted tooling, and console sessions under `bstoll`. All activity is on 2018-08-20 and breaks into three parts: a failed IAM persistence attempt, compute resource abuse, and a public S3 exposure that was reverted about an hour later. The `splunk_access` identity, despite its large call volume, is the Splunk AWS data collector and is ruled out as benign.

| Time (UTC) | Identity (source IP) | Action | Result |
|---|---|---|---|
| 09:16:12 | web_admin (35.153.154.221, Boto3) | CreateUser `my_db_user`, CreateAccessKey | Denied (AccessDenied) |
| 09:36:12 | bstoll (157.97.121.132, console) | UpdateAccessKey on web_admin | Key status changed |
| (same day) | web_admin (139.198.18.205, Boto3) | CreateDefaultVpc, RunInstances | Compute launched |
| 13:01:46 | bstoll (107.77.212.175, console) | PutBucketAcl frothlywebcode, grant AllUsers | Bucket public (read/write) |
| 13:57:54 | bstoll (107.77.212.175, console) | PutBucketAcl frothlywebcode, AllUsers removed | Bucket private |

The IAM persistence failed because `web_admin` lacked `iam:CreateUser` and `iam:CreateAccessKey`. The `frothlywebcode` bucket was world-accessible for about 56 minutes. Whether `bstoll` is the attacker, a compromised account, or an admin partly reacting cannot be settled from CloudTrail alone; that needs correlation with host and authentication logs, which is a thread for a later investigation.

## Questions

Each question records the SPL used, the finding, and whether it matched the official BOTS v3 answer key.

### Q1. What AWS API activity exists, and what are the busiest actions?

```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats count by eventName
| sort - count
```

Finding: 6,571 events across 113 distinct actions. The volume is dominated by read-only calls (`Describe*`, `List*`, `Get*`), consistent with routine tooling and SIEM collection. The write actions that stand out are `RunInstances` (582) and `AssumeRole` (332); these drive the rest of the investigation.

### Q2. Which identities and source IPs are calling the AWS API, and is there recon?

```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats count values(eventName) as actions by userIdentity.userName userIdentity.type sourceIPAddress userAgent
| sort - count
```

Finding: three identities matter.

- `splunk_access` (IAMUser) from `34.215.24.225` (AWS us-west-2, Boto3): heavy `Describe*`/`List*`/`Get*`. Assessed as the Splunk AWS add-on data collector, so its volume is expected. Ruled out as benign, documented so it is not chased later.
- `web_admin` (IAMUser), the key identity:
  - from `35.153.154.221`: `CreateUser`, `CreateAccessKey`, `GetSessionToken`, `DeleteAccessKey` — account/credential persistence.
  - from `139.198.18.205` (non-US): `CreateDefaultVpc`, `RunInstances` — standing up compute, consistent with resource hijacking.
- `bstoll` (IAMUser) from `107.77.212.175` (console): inventory sweep plus `PutBucketAcl`, `TerminateInstances`, and security-group edits. `PutBucketAcl` is a candidate for public S3 exposure.

Assessment: `web_admin` is the identity the attacker operated (leaked access key), used for persistence and compute abuse.

### Q3. What identity or credential was created or modified, and by whom?

```spl
index=botsv3 sourcetype=aws:cloudtrail
    (eventName=CreateUser OR eventName=CreateAccessKey OR eventName=CreateLoginProfile
     OR eventName=UpdateLoginProfile OR eventName=AttachUserPolicy OR eventName=PutUserPolicy
     OR eventName=DeleteAccessKey OR eventName=UpdateAccessKey)
| table _time userIdentity.userName eventName requestParameters.userName responseElements.user.userName responseElements.accessKey.accessKeyId responseElements.accessKey.userName sourceIPAddress userAgent
| sort _time
```

Finding: four events, all on 2018-08-20. At **09:16:12** `web_admin` attempts `CreateUser`, `CreateAccessKey`, and `DeleteAccessKey` within the same second from `35.153.154.221` (Boto3) — scripted, not console. The raw events show all three **failed** with `errorCode: AccessDenied`: `web_admin` is not authorized for `iam:CreateUser` (target user **`my_db_user`**) or `iam:CreateAccessKey`, and `requestParameters`/`responseElements` are null because the calls were denied. So the attacker, operating as `web_admin`, tried to establish IAM persistence by creating a user `my_db_user` and an access key, but was blocked by insufficient permissions. Twenty minutes later, at **09:36:12**, `bstoll` runs `UpdateAccessKey` on `web_admin` from the console (`157.97.121.132`), changing that key's status. Reading `errorCode` is what separates an attempted technique from a successful one.

### Q4. Was an S3 bucket exposed publicly, and which one?

```spl
index=botsv3 sourcetype=aws:cloudtrail
    (eventName=PutBucketAcl OR eventName=PutBucketPolicy OR eventName=PutObjectAcl)
| table _time userIdentity.userName eventName requestParameters.bucketName requestParameters.accessControlList sourceIPAddress userAgent
| sort _time
```

Finding: two `PutBucketAcl` calls on **`frothlywebcode`**, both by `bstoll` from the console (`107.77.212.175`). At **13:01:46** the ACL grants the group `http://acs.amazonaws.com/groups/global/AllUsers` (every user, i.e. public) `FULL_CONTROL`, `READ`, `WRITE`, `READ_ACP` — the bucket is world read/write. At **13:57:54** a second `PutBucketAcl` sets an ACL with only the `s3/LogDelivery` group, removing the `AllUsers` grant and returning the bucket to private. The public window is about 56 minutes.

### Q5. What source IPs and user agents did web_admin use across the chain?

```spl
index=botsv3 sourcetype=aws:cloudtrail userIdentity.userName=web_admin
| stats count values(eventName) as actions min(_time) as first max(_time) as last by sourceIPAddress userAgent
| sort - count
```

Finding: `web_admin` is seen from four external IPs in one day: `35.153.154.221` (IAM persistence attempt, Boto3), `139.198.18.205` (CreateDefaultVpc / RunInstances, Boto3, non-US), `82.102.18.111` (ElasticWolf), and `209.107.196.112` (ListAccessKeys, Boto3 on Windows). One IAM user operating from several unrelated IPs and tools in a single day is itself a strong compromise signal.

## ATT&CK techniques observed

Provisional, finalised after Q3 and Q4.

| Tactic | Technique | ID | Evidence in this investigation |
|---|---|---|---|
| Discovery | Cloud Infrastructure Discovery | T1580 | Broad `Describe*`/`List*` enumeration across EC2, IAM, S3 |
| Persistence | Create Account: Cloud Account | T1136.003 | `web_admin` attempts `CreateUser` (`my_db_user`) from `35.153.154.221` — denied (AccessDenied) |
| Persistence | Account Manipulation: Additional Cloud Credentials | T1098.001 | `web_admin` attempts `CreateAccessKey` — denied (AccessDenied) |
| Impact | Resource Hijacking | T1496 | `web_admin` runs `RunInstances` / `CreateDefaultVpc` from `139.198.18.205` |
| Collection | Data from Cloud Storage | T1530 | `bstoll` grants `AllUsers` FULL_CONTROL on `frothlywebcode` (public read/write) at 13:01:46, reverted 13:57:54 |

## Detection ideas

Behaviours from this investigation worth turning into Sigma rules (built in `detections/`):

- IAM `CreateUser` or `CreateAccessKey` by a non-administrative principal, or from an IP outside known admin ranges.
- `PutBucketAcl` / `PutBucketPolicy` granting access to `AllUsers` or `AuthenticatedUsers`.
- `RunInstances` from a source IP not previously seen for that principal.
- Same IAM user authenticating/operating from two widely separated geolocations in a short window (impossible travel).
