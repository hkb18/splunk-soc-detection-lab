# Windows Brute Force Login Simulation

## Objective

Simulate repeated failed SMB authentication attempts from a Kali Linux attacker VM against a Windows 10 FLARE VM and detect the activity in Splunk using Windows Security Event Logs.

---

## MITRE ATT&CK Mapping

Tactic: Credential Access  
Technique: Brute Force  
Technique ID: T1110

---

## Lab Environment

Attacker Machine: Kali Linux VM  
Target Machine: Windows 10 FLARE VM  
SIEM: Splunk Enterprise  
Log Source: Windows Security Event Logs

---

## Target Information

Windows Host IP: 192.168.56.101

![Windows Target IP Configuration](../screenshots/28_windows_target_ip_configuration.png)

---

## Preconditions

Before running the attack simulation the following configurations were verified:

- Windows target IP address confirmed
- Network connectivity from Kali to Windows verified
- SMB service accessible on Windows
- Windows audit policies enabled

Enabled audit policies:

- Logon
- Credential Validation
- Other Account Logon Events
- Account Lockout

![Windows Audit Policy Configuration](../screenshots/36_windows_audit_policy_configuration.png)

---

## Attack Simulation

A test account was targeted using repeated failed SMB authentication attempts.

Username used:

testuser

---

## Step 1 – Verify Network Connectivity

Command executed from Kali:

```
ping -c 4 192.168.56.101
```

![Kali Connectivity Test](../screenshots/29_kali_connectivity_test_ping.png)

---

## Step 2 – Attempt Single Failed Login

Command executed:

```
smbclient //192.168.56.101/SOCShare -U testuser%WrongPassword -c 'ls'
```

Expected output:

```
NT_STATUS_LOGON_FAILURE
```

---

## Step 3 – Simulate Brute Force Attempts

Command executed from Kali:

```
for i in {1..10}; do smbclient //192.168.56.101/SOCShare -U testuser%WrongPassword -c 'ls'; done
```

![Kali SMB Brute Force Attempts](../screenshots/31_kali_smb_bruteforce_attempts.png)

---

## Windows Log Evidence

The failed authentication attempts generate Windows Security log events.

Observed Event IDs:

4625 – An account failed to log on  
4776 – Credential validation attempt

---

## PowerShell Verification

Command used:

```
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625} -MaxEvents 10
```

![PowerShell Failed Logon Verification](../screenshots/32_windows_failed_logon_events_4625_powershell.png)

---

## Event Viewer Analysis

Event ID 4625 observed in Windows Security logs.

Important fields identified:

TargetUserName: testuser  
LogonType: 3  
AuthenticationPackageName: NTLM  
WorkstationName: HKB  
IpAddress: 192.168.56.103  
Status: 0xc000006d  
SubStatus: 0xc000006a  

These values indicate a failed network logon attempt caused by invalid credentials.

![Windows Event Viewer 4625 Details](../screenshots/33_windows_eventviewer_4625_details.png)

![Windows Event Viewer 4625 XML Details](../screenshots/35_windows_eventviewer_4625_xml_details.png)

---

## Credential Validation Event

Windows also generated credential validation events.

Event ID: 4776

![Windows Event Viewer 4776 Details](../screenshots/34_windows_eventviewer_4776_details.png)

---

## Splunk Log Validation

The Windows Security logs were successfully ingested into Splunk.

Search query used:

```
index=main sourcetype=XmlWinEventLog:Security "<EventID>4625</EventID>"
```

![Splunk Raw 4625 Logs](../screenshots/37_splunk_raw_eventid_4625_logs.png)

---

## Field Extraction

XML event fields were extracted using regular expressions.

Extracted fields:

- TargetUserName
- IpAddress
- LogonType
- WorkstationName
- Status
- SubStatus

![Splunk Field View](../screenshots/38_splunk_event_field_view.png)

![Splunk Unparsed Table View](../screenshots/39_splunk_initial_table_view_unparsed.png)

![Splunk Regex Field Extraction](../screenshots/40_splunk_regex_field_extraction_table.png)

---

## Detection Logic

The detection identifies multiple failed logon attempts within a short time window.

Detection condition:

5 or more failed login attempts within 5 minutes.

Detection query:

```spl
index=main sourcetype=XmlWinEventLog:Security "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]+)"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]+)"
| bin _time span=5m
| stats count values(IpAddress) as src_ip values(WorkstationName) as workstation values(LogonType) as logon_type by _time TargetUserName
| where count >= 5
| sort - count
```

---

## Detection Result

The query successfully detected repeated failed authentication attempts originating from the Kali attacker machine.

![Splunk Brute Force Detection Result](../screenshots/41_splunk_bruteforce_detection_results.png)