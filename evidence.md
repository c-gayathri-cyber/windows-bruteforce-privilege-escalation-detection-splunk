# Investigation Evidence and Findings

This document records the security events generated and investigated during the Windows security monitoring lab.

## 1. Lab Network Connectivity

| Component | Value |
|---|---|
| Host machine | DEVIL |
| Host IP | 192.168.56.1 |
| Target VM | SOC-Windows-Lab |
| Target VM IP | 192.168.56.102 |
| Network type | Host-only |
| SMB port | TCP 445 |

**Validation:** SMB connectivity was successfully tested between the host and Windows VM using TCP port 445.

## 2. Brute-Force Authentication Evidence

**Test account:** bruteuser

| Field | Observed value |
|---|---|
| Failed login Event ID | 4625 |
| Successful login Event ID | 4624 |
| Source IP | 192.168.56.1 |
| Logon Type | 3 |
| Failure Status | 0xC000006D |
| Failure SubStatus | 0xC000006A |
| Authentication | NTLM |

**Finding:** Controlled failed SMB authentication attempts were generated from the host machine. Windows Security logs recorded the failures with the expected source IP and Logon Type 3.

## 3. Failed Login Followed by Successful Login

| Field | Observed value |
|---|---|
| Failed login Event ID | 4625 |
| Successful login Event ID | 4624 |
| Account | bruteuser |
| Source IP | 192.168.56.1 |
| Failed attempt timestamp | 2026-11-21 00:08:18.580 |
| Successful login timestamp | 2026-11-21 00:09:36.665 |
| Previous failures detected | 1 |

**Finding:** Splunk successfully correlated a failed authentication followed by a successful authentication from the same source IP and account within the 10-minute window.

## 4. New Account Creation Evidence

| Field | Observed value |
|---|---|
| Event ID | 4720 |
| Created account | testuser |
| Created by | SOCUser |
| Event timestamp | 2026-11-20 23:51:49.436 |

**Finding:** Windows Security Event ID 4720 confirmed the creation of the test account.

## 5. Local Administrators Group Change Evidence

| Field | Observed value |
|---|---|
| Event ID | 4732 |
| Added account | testuser |
| Target group | Administrators |
| Changed by | SOCUser |
| Event timestamp | 2026-11-20 23:52:10.784 |
| Member SID | S-1-5-21-505756408-1876722126-2513164340-1003 |

**Finding:** Event ID 4732 confirmed that the test account was added to the local Administrators group. The member SID was matched with the SID of testuser.

This demonstrates controlled privilege elevation through local group membership modification, not exploitation of a vulnerability.

## 6. Splunk Alert Validation

| Alert | Validation |
|---|---|
| Windows Brute-Force Detection | Triggered and verified |
| Failed Login Followed by Successful Login | Triggered and verified |
| Windows New Account Creation Detection | Triggered and verified |
| Windows - Local Administrators Group Change | Triggered and verified |

All four alerts were configured as scheduled searches and their triggering activity was observed in Splunk Triggered Alerts.

## 7. Log Forwarding Verification

Splunk search results confirmed Windows Security log ingestion:

| Host | Source | Sourcetype | Event count |
|---|---|---|---:|
| SOC-Windows-Lab | WinEventLog:Security | XmlWinEventLog:Security | 22,783 |

Observed event counts during validation:

| Event ID | Count |
|---|---:|
| 4624 | 1,415 |
| 4625 | 20 |
| 4720 | 5 |
| 4732 | 11 |

These counts represent the observed lab data at the time of validation, not necessarily unique test events.

## 8. Investigation Conclusion

The lab successfully demonstrated:

- Network-based Windows authentication monitoring.
- Detection of repeated failed login attempts.
- Correlation of failed and successful authentication events.
- Detection of new local account creation.
- Detection of local Administrators group membership changes.
- Splunk alert configuration and validation.
