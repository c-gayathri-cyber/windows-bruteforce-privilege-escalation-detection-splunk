# SOC Investigation Notes

## 1. Lab Architecture

The project uses an isolated host-only network.

- Host machine: Windows laptop
- Target: Windows 11 VirtualBox VM
- SIEM: Splunk Enterprise
- Log collection: Splunk Universal Forwarder
- Log source: Windows Security Event Logs

## 2. Investigation Workflow

### Step 1: Verify Network Connectivity

- Identified the host and target VM IP addresses.
- Tested SMB connectivity over TCP port 445.
- Confirmed communication between the two lab systems.

### Step 2: Generate Authentication Events

- Used a test account named `bruteuser`.
- Generated controlled failed SMB authentication attempts.
- Performed a successful SMB authentication.
- Examined Windows Event IDs 4625 and 4624.

### Step 3: Investigate Authentication Activity

- Extracted account names and source IP addresses using SPL.
- Identified Logon Type 3 network authentication.
- Correlated failed authentication attempts with a subsequent successful login.
- Implemented a rolling 10-minute detection window.

### Step 4: Investigate Account Creation

- Created a controlled test account named `testuser`.
- Examined Event ID 4720.
- Identified the account creator and newly created username.

### Step 5: Investigate Privileged Group Changes

- Added `testuser` to the local Administrators group.
- Examined Event ID 4732.
- Matched the member SID with the test account SID.
- Verified the group membership change.

### Step 6: Configure and Validate Alerts

Configured scheduled Splunk alerts for:

- Repeated failed login attempts.
- Failed login followed by successful login.
- New account creation.
- Local Administrators group membership changes.

Verified alert activity in Splunk Triggered Alerts.

## 3. Important Windows Event IDs

| Event ID | Investigation meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4720 | User account created |
| 4732 | Member added to local security-enabled group |

## 4. Investigation Observations

- Network authentication attempts were recorded with the host machine's IP address.
- Failed login events contained the expected failure status and substatus.
- Splunk successfully correlated failed and successful authentication events.
- New account creation was identified through Event ID 4720.
- Local Administrators group membership modification was identified through Event ID 4732.
- Scheduled alerts successfully triggered for the tested activities.

## 5. Limitations and Improvements

- The project was performed in an isolated virtual lab.
- Privilege elevation was simulated through controlled group membership modification, not vulnerability exploitation.
- Alerts were configured as scheduled searches rather than real-time detections.
- Repeated scheduled alert triggers can cause alert fatigue.
- Production deployment should include alert suppression, deduplication and improved correlation logic.

## 6. Learning Outcomes

- Windows Security Event Log investigation.
- Splunk SPL search development.
- Authentication monitoring and correlation.
- Account management event analysis.
- Local privilege change monitoring.
- SIEM alert configuration and validation.
- Basic MITRE ATT&CK mapping.
