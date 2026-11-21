# Splunk Detection Queries

This document contains the SPL queries developed and validated in the Windows Brute-Force and Privilege Escalation Detection project.

## 1. Brute-Force Detection

**Objective:** Detect five or more failed login attempts within a rolling 10-minute window from the same test source and account.

**Windows Event ID:** 4625

```spl
index=* sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| where EventCode="4625"
    AND TargetUserName="bruteuser"
    AND IpAddress="192.168.56.1"
| sort 0 _time
| streamstats time_window=10m count as Failed_Attempts
| where Failed_Attempts >= 5
| table _time TargetUserName IpAddress Failed_Attempts
```

**Validated result:** Detected five failed login attempts from `192.168.56.1` against `bruteuser` within the rolling 10-minute window.

## 2. Failed Login Followed by Successful Login

**Objective:** Identify a successful login when at least one failed login occurred within the previous 10 minutes for the same account and source IP.

**Windows Event IDs:** 4625, 4624

```spl
index=* sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| where EventCode="4625" OR EventCode="4624"
| where TargetUserName="bruteuser" AND IpAddress="192.168.56.1"
| sort 0 _time
| streamstats time_window=10m count(eval(EventCode="4625")) as Previous_Failures by TargetUserName IpAddress
| where EventCode="4624" AND Previous_Failures>=1
| table _time EventCode TargetUserName IpAddress Previous_Failures
```

**Validated result:** Detected a successful login following a failed login from the same source IP and account.

## 3. Windows Account Creation Detection

**Objective:** Monitor newly created Windows user accounts.

**Windows Event ID:** 4720

```spl
index=* sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<CreatedBy>[^<]+)</Data>"
| where EventCode="4720"
| table _time EventCode TargetUserName CreatedBy
| sort -_time
```

**Validated result:** Detected creation of the `testuser` account by `SOCUser`.

## 4. Local Administrators Group Change Detection

**Objective:** Detect users added to the local Administrators group.

**Windows Event ID:** 4732

```spl
index=* sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='MemberSid'>(?<MemberSid>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetUserName'>(?<GroupName>[^<]+)</Data>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<ChangedBy>[^<]+)</Data>"
| where EventCode="4732" AND GroupName="Administrators"
| table _time EventCode GroupName MemberSid ChangedBy
| sort -_time
```

**Validated result:** Detected the addition of the `testuser` account to the local Administrators group. The member SID was matched against the test account SID.

---

## Notes

- All queries were tested in the isolated Windows lab environment.
- Windows Security events were collected using Splunk Universal Forwarder.
- SPL searches were executed in Splunk Enterprise.
- The brute-force and login-correlation queries use the actual lab test account and host-only IP address.
- Account creation and Administrators group change searches monitor their respective event types.
