\# Suspicious PowerShell Execution Detection



\## Objective



This lab demonstrates how suspicious PowerShell execution can be detected on a Windows 10 FLARE VM using Splunk, Sysmon, and native PowerShell Operational logging.



The goal was to simulate suspicious PowerShell activity commonly associated with attacker tradecraft and validate that the activity could be identified in Splunk using command-line telemetry.



\## Environment



\- \*\*Target Host:\*\* Windows 10 FLARE VM

\- \*\*SIEM:\*\* Splunk Enterprise 10.2.1

\- \*\*Endpoint Telemetry:\*\* Sysmon

\- \*\*Native Logging:\*\* Microsoft-Windows-PowerShell/Operational

\- \*\*Virtualization:\*\* Oracle VirtualBox

\- \*\*Network Mode:\*\* Host-Only Adapter



\## Log Sources Used



Two primary log sources were used for this detection:



1\. \*\*Sysmon Operational Log\*\*

&nbsp;  - Sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

&nbsp;  - Key Event ID: `1` (Process Creation)



2\. \*\*PowerShell Operational Log\*\*

&nbsp;  - Sourcetype: `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`



The Sysmon process creation events were used as the main detection source because they exposed command-line arguments such as `-NoProfile`, `-EncodedCommand`, `-ExecutionPolicy Bypass`, and `-WindowStyle Hidden`.



The PowerShell Operational log was enabled to provide richer native PowerShell execution telemetry for validation and future detection expansion.



\## Telemetry Preparation



Before generating suspicious activity, the following validation steps were completed:



\- Confirmed the `sysmon64` service was running

\- Confirmed Sysmon events were visible in Event Viewer

\- Confirmed Splunk was ingesting Sysmon logs

\- Enabled PowerShell Script Block Logging

\- Enabled PowerShell Module Logging

\- Enabled PowerShell Transcription

\- Added `Microsoft-Windows-PowerShell/Operational` to Splunk `inputs.conf`

\- Forced Group Policy refresh with `gpupdate /force`



\## PowerShell Logging Configuration



PowerShell logging was enabled through Local Group Policy Editor using:



```text

Computer Configuration

→ Administrative Templates

→ Windows Components

→ Windows PowerShell

```



The following settings were enabled:



\- \*\*Turn on Module Logging\*\*

\- \*\*Turn on PowerShell Script Block Logging\*\*

\- \*\*Turn on PowerShell Transcription\*\*



This ensured that PowerShell execution generated both Sysmon process creation events and native PowerShell Operational logs.



\## Splunk Ingestion Configuration



The following stanza was added to the Splunk `inputs.conf` file:



```ini

\[WinEventLog://Microsoft-Windows-PowerShell/Operational]

disabled = 0

index = main

renderXml = true

start\_from = oldest

current\_only = 0

```



This allowed Splunk to ingest PowerShell Operational events in XML format for later analysis.



\## Baseline Validation



Sysmon ingestion was validated in Splunk using:



```spl

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

| rex "<EventID>(?<event\_id>\\d+)</EventID>"

| stats count by event\_id

| sort event\_id

```



The event distribution confirmed the presence of multiple Sysmon event types, including:



\- Event ID 1 – Process Creation

\- Event ID 3 – Network Connection

\- Event ID 11 – File Creation

\- Event ID 12 / 13 – Registry Activity

\- Event ID 22 – DNS Query



This confirmed that the Sysmon telemetry pipeline was functioning correctly.



\## Attack Simulation



Two safe PowerShell execution tests were performed locally on the FLARE VM.



\### Test 1 — Suspicious PowerShell Flags



The following command was executed to simulate a suspicious PowerShell process using common attacker-style arguments:



```powershell

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$env:TEMP | Out-File $env:TEMP\\ps\_test.txt"

```



This command was chosen because it includes multiple suspicious indicators often seen in malicious or evasive PowerShell tradecraft:



\- `-NoProfile`

\- `-ExecutionPolicy Bypass`

\- `-WindowStyle Hidden`



\### Test 2 — Encoded PowerShell Execution



An encoded PowerShell command was generated and then executed.



The following commands were used to generate the Base64 payload:



```powershell

$cmd = 'Start-Process notepad'

$bytes = \[System.Text.Encoding]::Unicode.GetBytes($cmd)

$enc = \[Convert]::ToBase64String($bytes)

$enc

```



The encoded payload was then executed with:



```powershell

powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <BASE64\_VALUE>

```



This opened Notepad while also generating process creation telemetry consistent with suspicious encoded PowerShell usage.



\## Detection Logic



The detection focuses on \*\*Sysmon Event ID 1\*\* and identifies PowerShell processes whose command lines contain suspicious flags or indicators.



The query extracts these fields from raw XML:



\- `Image`

\- `CommandLine`

\- `ParentImage`



It then filters for PowerShell process executions containing indicators such as:



\- `-nop`

\- `-noprofile`

\- `-enc`

\- `-encodedcommand`

\- `-executionpolicy bypass`

\- `-w hidden`

\- `-windowstyle hidden`

\- `iex`

\- `downloadstring`

\- `webclient`



\## Splunk Detection Query



```spl

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

| rex "<EventID>(?<event\_id>\\d+)</EventID>"

| search event\_id=1

| rex field=\_raw "<Data Name='Image'>(?<Image>\[^<]+)</Data>"

| rex field=\_raw "<Data Name='CommandLine'>(?<CommandLine>\[^<]+)</Data>"

| rex field=\_raw "<Data Name='ParentImage'>(?<ParentImage>\[^<]+)</Data>"

| search Image="\*\\\\powershell.exe"

| eval cmd=lower(CommandLine)

| where like(cmd,"% -nop%")

&nbsp;   OR like(cmd,"% -noprofile%")

&nbsp;   OR like(cmd,"% -enc%")

&nbsp;   OR like(cmd,"% -encodedcommand%")

&nbsp;   OR like(cmd,"% -executionpolicy bypass%")

&nbsp;   OR like(cmd,"% -w hidden%")

&nbsp;   OR like(cmd,"% -windowstyle hidden%")

&nbsp;   OR like(cmd,"%iex%")

&nbsp;   OR like(cmd,"%downloadstring%")

&nbsp;   OR like(cmd,"%webclient%")

| table \_time Image ParentImage CommandLine

| sort - \_time

```



\## Detection Result



The query successfully identified the locally executed suspicious PowerShell commands.



Observed behaviors included:



\- PowerShell executed with `-NoProfile`

\- PowerShell executed with `-ExecutionPolicy Bypass`

\- PowerShell executed with `-WindowStyle Hidden`

\- PowerShell executed with `-EncodedCommand`



This confirmed that the detection logic worked as intended and that the suspicious command lines were visible through Sysmon process creation telemetry in Splunk.



\## Additional Validation



PowerShell Operational logs were also successfully ingested in Splunk using:



```spl

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"

| table \_time \_raw

| sort - \_time

```



This confirmed that native PowerShell logging was working and could support future detection improvements using events such as Script Block Logging.



\## MITRE ATT\&CK Mapping



\- \*\*Tactic:\*\* Execution

\- \*\*Technique:\*\* T1059.001 – PowerShell



\## Analyst Notes



This detection is intentionally based on behavioral indicators rather than a specific malware family.



Key analyst takeaways:



1\. \*\*Sysmon Event ID 1\*\* is a strong source for detecting suspicious PowerShell command-line execution.

2\. Native \*\*PowerShell Operational logging\*\* provides useful supporting context for deeper investigations.

3\. Encoded commands and hidden-window execution are high-value indicators in endpoint telemetry.

4\. This detection can be expanded later to include:

&nbsp;  - `pwsh.exe`

&nbsp;  - Script Block Logging events

&nbsp;  - download cradles

&nbsp;  - parent-child process anomalies



\## Evidence Screenshots



The following screenshots support this detection:



\- Sysmon service running

\- Event Viewer showing Sysmon Operational logs

\- Splunk Sysmon event ID distribution

\- Local Group Policy with PowerShell logging enabled

\- `gpupdate /force` success

\- `inputs.conf` updated for PowerShell Operational logs

\- Encoded PowerShell execution on the FLARE VM

\- Splunk detection results showing suspicious PowerShell command lines

\- PowerShell Operational logs visible in Splunk

