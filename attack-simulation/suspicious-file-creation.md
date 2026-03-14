# Suspicious File Creation Detection

## Overview

This detection identifies suspicious file creation activity in directories commonly abused by attackers for malware staging and execution.

Attackers frequently drop payloads into directories such as **Temp**, **AppData**, or **Public user folders** before executing them. Monitoring file creation activity in these locations can help detect early-stage malicious activity.

This detection uses **Sysmon Event ID 11 (FileCreate)** telemetry collected from Windows endpoints and analyzed in Splunk.

---

## Log Source

**Sysmon Operational Log**

Event:

```
Event ID 11 – FileCreate
```

Sysmon provides detailed telemetry including the process responsible for creating the file and the full file path.

---

## Attack Simulation

To simulate malware staging behavior, test payload files were written to commonly abused directories using PowerShell.

### PowerShell Commands

```
"test payload" | Out-File "$env:TEMP\stage_payload.exe"
"test payload" | Out-File "$env:APPDATA\chrome_update.exe"
"test payload" | Out-File "C:\Users\Public\adobe_patch.bat"
```

### Attack Simulation Evidence

![File Creation Attack Simulation](../screenshots/24_FileCreate_Attack_Simulation_PowerShell.png)

---

## Endpoint Telemetry Evidence

Sysmon generated a **FileCreate event (Event ID 11)** confirming that the file was written to the target directory.

Important fields observed in the event:

- Image (process responsible for file creation)
- TargetFilename
- ProcessId
- User

### Sysmon Event Viewer Evidence

![Sysmon EventID 11 File Creation](../screenshots/25_Sysmon_EventID11_FileCreate_Event_Details.png)

---

## SIEM Log Ingestion

The Sysmon logs were successfully ingested into Splunk using the Windows Event Log input.

A raw search for the generated file confirmed that the event was present in the SIEM.

### Raw Splunk Event Evidence

![Splunk Raw File Creation Event](../screenshots/26_Splunk_Raw_FileCreate_Event_Search.png)

---

## Detection Query

The following Splunk query identifies suspicious file creation events in directories commonly used by attackers.

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational "<EventID>11</EventID>"
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| search TargetFilename="*Temp*" OR TargetFilename="*AppData*" OR TargetFilename="*Public*"
| table _time host Image TargetFilename
```

---

## Detection Result

The detection query successfully identified the simulated payload written to the **AppData** directory.

### Detection Output

![Splunk Detection Result](../screenshots/27_Splunk_FileCreate_Detection_Result.png)

---

## MITRE ATT&CK Mapping

Relevant MITRE ATT&CK techniques:

```
T1105 – Ingress Tool Transfer
T1204 – User Execution
```

These techniques often involve staging malicious payloads in user-accessible directories prior to execution.

---

## Conclusion

This detection demonstrates how **Sysmon endpoint telemetry combined with SIEM analysis in Splunk** can identify suspicious file creation behavior associated with malware staging.

Monitoring abnormal file creation paths is an effective technique for detecting early attacker activity in Windows environments.'[