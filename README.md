# Splunk SOC Detection Lab

This project demonstrates how to build a small Security Operations Center (SOC) detection lab using Splunk, Sysmon, and a simulated attacker environment.

The lab collects telemetry from a Windows endpoint, simulates attacker activity, and demonstrates how suspicious behavior can be identified using Splunk queries.

------------------------------------------------------------

## Lab Overview

Architecture used in this lab:

- Windows 10 FLARE VM (Target System)
- Kali Linux VM (Attacker)
- Splunk Enterprise 10.2.1 (SIEM Platform)
- Sysmon (Endpoint Telemetry Collection)
- Oracle VirtualBox (Virtualization Platform)

The objective is to simulate attacker reconnaissance activity and detect it using Splunk.

------------------------------------------------------------

## Splunk Platform

Splunk Enterprise was installed on the Windows target VM to collect and analyze security telemetry.

### Splunk Login

![Splunk Login](screenshots/01_Splunk_Login_Page.png)

### Splunk Dashboard

![Splunk Dashboard](screenshots/02_Splunk_Dashboard_Home.png)

### Splunk Version

![Splunk Version](screenshots/03_Splunk_Enterprise_Version.png)

------------------------------------------------------------

## Sysmon Telemetry

Sysmon was deployed to enhance Windows logging capabilities and provide detailed endpoint telemetry including process activity, network connections, and file creation events.

### Sysmon Logs in Splunk

![Sysmon Logs](screenshots/05_Sysmon_Logs_Ingested_in_Splunk.png)

### Sysmon Event Distribution

![Sysmon Event Statistics](screenshots/06_Sysmon_EventID_Statistics.png)

These logs confirm that endpoint telemetry is successfully being ingested into Splunk.

------------------------------------------------------------

## Attack Simulation

A reconnaissance scan was executed from the Kali Linux attacker VM against the Windows target.

During testing, multiple scan techniques were evaluated including:

nmap -sT 192.168.56.101  
nmap -sS 192.168.56.101  
nmap -sT -p- 192.168.56.101  

For documentation purposes, the screenshot evidence below shows the full TCP port scan using:

nmap -sT -p- 192.168.56.101

This scan attempts to connect to all TCP ports on the target system and generates multiple network connection events visible in Windows Security logs.

### Nmap Scan Evidence

![Kali Nmap Scan](screenshots/08_Kali_Nmap_Port_Scan.png)

------------------------------------------------------------

## Port Scan Detection

To identify scanning behavior, Windows Security Event ID 5156 was analyzed in Splunk.

A detection query was created to identify hosts attempting connections to many distinct destination ports within a short time window.

### Detection Query Result

![Port Scan Detection](screenshots/09_Splunk_Port_Scan_Detection.png)

### Time-Based Correlation

![Time Based Detection](screenshots/11_Time_Based_Port_Scan_Detection.png)

### Final Detection Result

![Final Detection Result](screenshots/12_Final_Port_Scan_Detection_Result.png)

The detection successfully identified host:

192.168.56.103

as performing port scanning activity against the Windows target system.

### MITRE ATT&CK Mapping

Tactic: Reconnaissance  
Technique: T1046 – Network Service Discovery

------------------------------------------------------------

## Suspicious PowerShell Execution Detection

In addition to reconnaissance detection, the lab also demonstrates how suspicious PowerShell execution can be identified using Sysmon process telemetry.

PowerShell logging was enabled using Local Group Policy to capture detailed script activity.

The following logging features were enabled:

- PowerShell Script Block Logging
- PowerShell Module Logging
- PowerShell Transcription

These settings ensure that PowerShell activity generates detailed telemetry in both Sysmon logs and native PowerShell Operational logs.

### Sysmon Verification

![Sysmon Running](screenshots/13_Sysmon_Service_Running.png)

### Sysmon Event Viewer Log

![Sysmon Event Viewer](screenshots/14_Sysmon_Event_Viewer_Operational_Log.png)

### Sysmon Event ID Statistics

![Sysmon Event Statistics](screenshots/15_Sysmon_EventID_Statistics.png)

### PowerShell Logging Configuration

![PowerShell Logging](screenshots/16_PowerShell_Logging_Group_Policy.png)

### Policy Update

![GPUpdate](screenshots/17_GPUpdate_Force_Success.png)

### Splunk Input Configuration

PowerShell Operational logs were added to Splunk ingestion using the following configuration.

![Inputs Configuration](screenshots/18_Splunk_Inputs_PowerShell_Operational.png)

------------------------------------------------------------

### Attack Simulation

Suspicious PowerShell commands were executed locally on the Windows FLARE VM to simulate attacker behavior.

Example execution:

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$env:TEMP | Out-File $env:TEMP\ps_test.txt"

Encoded PowerShell execution was also simulated using the EncodedCommand flag.

### Encoded PowerShell Execution

![Encoded PowerShell](screenshots/19_Suspicious_PowerShell_Encoded_Command.png)

------------------------------------------------------------

### Detection Logic

Sysmon Event ID 1 (Process Creation) was analyzed in Splunk to identify suspicious PowerShell command line arguments such as:

- -NoProfile
- -EncodedCommand
- -ExecutionPolicy Bypass
- -WindowStyle Hidden

### Sysmon Event ID 1 Search

![Sysmon EventID1 Search](screenshots/22_Sysmon_PowerShell_EventID1_Search.png)

### Process Creation Results

![Process Creation Results](screenshots/23_Sysmon_PowerShell_Process_Creation_Results.png)

------------------------------------------------------------

### Detection Result

The Splunk query successfully identified the suspicious PowerShell executions generated during the simulation.

![PowerShell Detection](screenshots/20_Splunk_PowerShell_Detection_Result.png)

PowerShell Operational logs were also confirmed to be successfully ingested into Splunk.

![PowerShell Operational Logs](screenshots/21_PowerShell_Operational_Logs_In_Splunk.png)

### MITRE ATT&CK Mapping

Tactic: Execution  
Technique: T1059.001 – PowerShell

------------------------------------------------------------

## Suspicious File Creation Detection

Attackers frequently stage payloads or drop tools into user-accessible directories before executing them.

Common directories used include:

- %TEMP%
- %APPDATA%
- C:\Users\Public\

Sysmon Event ID 11 (FileCreate) provides visibility into file creation activity on the system.

------------------------------------------------------------

### Attack Simulation

To simulate malware staging behavior, files were created in commonly abused directories using PowerShell.

Example commands executed on the Windows FLARE VM:

"test payload" | Out-File "$env:TEMP\stage_payload.exe"  
"test payload" | Out-File "$env:APPDATA\chrome_update.exe"  
"test payload" | Out-File "C:\Users\Public\adobe_patch.bat"

### Attack Simulation Evidence

![File Creation Attack](screenshots/24_FileCreate_Attack_Simulation_PowerShell.png)

------------------------------------------------------------

### Sysmon Telemetry Evidence

The file creation activity generated Sysmon Event ID 11 (FileCreate) events which were recorded in the Windows Sysmon Operational log.

### Sysmon Event Viewer Evidence

![Sysmon FileCreate Event](screenshots/25_Sysmon_EventID11_FileCreate_Event_Details.png)

------------------------------------------------------------

### Splunk Log Verification

The generated file creation event was successfully ingested into Splunk.

A raw search for the created file confirmed the presence of the event.

### Raw Event in Splunk

![Splunk Raw FileCreate Event](screenshots/26_Splunk_Raw_FileCreate_Event_Search.png)

------------------------------------------------------------

### Detection Logic

A Splunk detection query was created to identify file creation events in directories commonly abused by attackers.

The detection focuses on Sysmon Event ID 11 events where files are written to:

- Temp directories
- AppData directories
- Public user folders

### Detection Result

![File Creation Detection Result](screenshots/27_Splunk_FileCreate_Detection_Result.png)

The detection successfully identified the simulated payload creation activity during the attack simulation.

### MITRE ATT&CK Mapping

Tactic: Defense Evasion  
Technique: T1105 – Ingress Tool Transfer

------------------------------------------------------------

## Windows Brute Force Login Detection

In addition to endpoint and reconnaissance detections, the lab also demonstrates detection of brute force login attempts against the Windows system.

The attack was simulated from the Kali Linux attacker VM using repeated failed SMB authentication attempts against the Windows host.

### Attack Simulation

The attacker attempted multiple failed logins against a test user account.

Target Windows IP:

192.168.56.101

### Connectivity Verification

![Kali Connectivity Test](screenshots/29_kali_connectivity_test_ping.png)

### Brute Force Attempt Simulation

![Kali SMB Brute Force Attempts](screenshots/31_kali_smb_bruteforce_attempts.png)

These failed authentication attempts generated Windows Security log events.

Relevant Windows Event IDs:

4625 – An account failed to log on  
4776 – Credential validation attempt

### Windows Event Evidence

![Windows Event 4625](screenshots/33_windows_eventviewer_4625_details.png)

![Windows Event 4776](screenshots/34_windows_eventviewer_4776_details.png)

### Splunk Log Verification

The failed authentication events were successfully ingested into Splunk.

![Splunk Raw Event 4625](screenshots/37_splunk_raw_eventid_4625_logs.png)

### Detection Query

The following SPL query was used to detect brute force login activity.

```spl
index=main sourcetype=XmlWinEventLog:Security "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]+)"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]+)"
| bin _time span=5m
| stats count values(IpAddress) as src_ip values(WorkstationName) as workstation by _time TargetUserName
| where count >= 5
| sort - count
```

### Detection Result

![Brute Force Detection](screenshots/41_splunk_bruteforce_detection_results.png)

### MITRE ATT&CK Mapping

Tactic: Credential Access  
Technique: T1110 – Brute Force

------------------------------------------------------------

## SOC Detection Dashboard

A Splunk monitoring dashboard was created to visualize detection activity across the simulated attack scenarios. This dashboard provides a SOC-style monitoring view across authentication activity, network activity, process execution, and file system monitoring.

### Dashboard Panels

- Failed Login Attempts (Brute Force Detection)
- Potential Port Scanning Hosts
- Suspicious PowerShell Execution
- Suspicious File Creation Activity

### Dashboard Visualizations

![Authentication and Network Monitoring](screenshots/42_splunk_soc_dashboard_authentication_network_monitoring.png)

![Process and File Monitoring](screenshots/43_splunk_soc_dashboard_process_file_monitoring.png)

### Dashboard Export

The exported dashboard file can be found here:

dashboard/soc_detection_dashboard.pdf

------------------------------------------------------------

## Repository Structure

```
splunk-soc-detection-lab
│
├─ README.md
├─ documentation
│   └─ lab-setup.md
├─ attack-simulation
│   ├─ nmap-scan.md
│   ├─ suspicious-powershell.md
│   ├─ suspicious-file-creation.md
│   └─ brute-force-logon.md
├─ queries
│   ├─ port-scan-detection.spl
│   ├─ suspicious-powershell-detection.spl
│   ├─ suspicious-file-creation-detection.spl
│   └─ brute-force-login-detection.spl
├─ dashboard
│   └─ soc_detection_dashboard.pdf
└─ screenshots
```

------------------------------------------------------------

## Outcome

This lab demonstrates how endpoint telemetry can be collected, analyzed, and used to detect malicious behavior using Splunk SIEM.

The project highlights the process of:

- Deploying endpoint telemetry
- Collecting logs in a SIEM platform
- Simulating attacker activity
- Building detection logic to identify malicious behavior
- Detecting brute force login attempts using Windows Security logs