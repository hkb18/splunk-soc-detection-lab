\# Windows Brute Force Login Simulation



\## Objective



Simulate repeated failed SMB authentication attempts from a Kali Linux attacker VM against a Windows 10 FLARE VM and detect the activity in Splunk using Windows Security Event Logs.



\---



\## MITRE ATT\&CK Mapping



Tactic: Credential Access  

Technique: Brute Force  

Technique ID: T1110



\---



\## Lab Environment



Attacker Machine: Kali Linux VM  

Target Machine: Windows 10 FLARE VM  

SIEM: Splunk Enterprise  

Log Source: Windows Security Event Logs



\---



\## Target Information



Windows Host IP: 192.168.56.101



!\[Windows Target IP Configuration](../screenshots/28\_windows\_target\_ip\_configuration.png)



\---



\## Preconditions



Before running the attack simulation the following configurations were verified:



\- Windows target IP address confirmed

\- Network connectivity from Kali to Windows verified

\- SMB service accessible on Windows

\- Windows audit policies enabled



Enabled audit policies:



\- Logon

\- Credential Validation

\- Other Account Logon Events

\- Account Lockout



!\[Windows Audit Policy Configuration](../screenshots/36\_windows\_audit\_policy\_configuration.png)



\---



\## Attack Simulation



A test account was targeted using repeated failed SMB authentication attempts.



Username used:



testuser



\---



\## Step 1 – Verify Network Connectivity



Command executed from Kali:



&#x20;   ping -c 4 192.168.56.101



!\[Kali Connectivity Test](../screenshots/29\_kali\_connectivity\_test\_ping.png)



\---



\## Step 2 – Attempt Single Failed Login



Command executed:



&#x20;   smbclient //192.168.56.101/SOCShare -U testuser%WrongPassword -c 'ls'



Expected output:



&#x20;   NT\_STATUS\_LOGON\_FAILURE



\---



\## Step 3 – Simulate Brute Force Attempts



Command executed from Kali:



&#x20;   for i in {1..10}; do smbclient //192.168.56.101/SOCShare -U testuser%WrongPassword -c 'ls'; done



!\[Kali SMB Brute Force Attempts](../screenshots/31\_kali\_smb\_bruteforce\_attempts.png)



\---



\## Windows Log Evidence



The failed authentication attempts generate Windows Security log events.



Observed Event IDs:



4625 – An account failed to log on  

4776 – Credential validation attempt



\---



\## PowerShell Verification



Command used:



&#x20;   Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625} -MaxEvents 10



!\[PowerShell Failed Logon Verification](../screenshots/32\_windows\_failed\_logon\_events\_4625\_powershell.png)



\---



\## Event Viewer Analysis



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



!\[Windows Event Viewer 4625 Details](../screenshots/33\_windows\_eventviewer\_4625\_details.png)



!\[Windows Event Viewer 4625 XML Details](../screenshots/35\_windows\_eventviewer\_4625\_xml\_details.png)



\---



\## Credential Validation Event



Windows also generated credential validation events.



Event ID: 4776



!\[Windows Event Viewer 4776 Details](../screenshots/34\_windows\_eventviewer\_4776\_details.png)



\---



\## Splunk Log Validation



The Windows Security logs were successfully ingested into Splunk.



Search query used:



&#x20;   index=main sourcetype=XmlWinEventLog:Security "<EventID>4625</EventID>"



!\[Splunk Raw 4625 Logs](../screenshots/37\_splunk\_raw\_eventid\_4625\_logs.png)



\---



\## Field Extraction



XML event fields were extracted using regular expressions.



Extracted fields:



\- TargetUserName

\- IpAddress

\- LogonType

\- WorkstationName

\- Status

\- SubStatus



!\[Splunk Field View](../screenshots/38\_splunk\_event\_field\_view.png)



!\[Splunk Unparsed Table View](../screenshots/39\_splunk\_initial\_table\_view\_unparsed.png)



!\[Splunk Regex Field Extraction](../screenshots/40\_splunk\_regex\_field\_extraction\_table.png)



\---



\## Detection Logic



The detection identifies multiple failed logon attempts within a short time window.



Detection condition:



5 or more failed login attempts within 5 minutes.



Detection query:



&#x20;   index=main sourcetype=XmlWinEventLog:Security "<EventID>4625</EventID>"

&#x20;   | rex field=\_raw "<Data Name='TargetUserName'>(?<TargetUserName>\[^<]+)"

&#x20;   | rex field=\_raw "<Data Name='IpAddress'>(?<IpAddress>\[^<]+)"

&#x20;   | rex field=\_raw "<Data Name='LogonType'>(?<LogonType>\[^<]+)"

&#x20;   | rex field=\_raw "<Data Name='WorkstationName'>(?<WorkstationName>\[^<]+)"

&#x20;   | bin \_time span=5m

&#x20;   | stats count values(IpAddress) as src\_ip values(WorkstationName) as workstation values(LogonType) as logon\_type by \_time TargetUserName

&#x20;   | where count >= 5

&#x20;   | sort - count



\---



\## Detection Result



The query successfully detected repeated failed authentication attempts originating from the Kali attacker machine.



!\[Splunk Brute Force Detection Result](../screenshots/41\_splunk\_bruteforce\_detection\_results.png)

