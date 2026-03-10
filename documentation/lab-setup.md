\# Lab Setup



\## Objective

Build a SOC-style detection lab using Splunk Enterprise, Sysmon, a Windows 10 FLARE VM, and a Kali Linux attacker VM. The objective of the lab is to generate telemetry, ingest it into Splunk, and build detection logic for attacker activity.



\## Lab Components



\### Target System

\- Windows 10 FLARE VM

\- Splunk Enterprise 10.2.1

\- Sysmon

\- Windows Event Logs



\### Attacker System

\- Kali Linux

\- Nmap



\### Virtualization

\- Oracle VirtualBox



\## Network Design

The lab used host-only networking during attack simulation so the Kali VM could communicate directly with the Windows target.



Observed addressing during the lab:

\- Windows target: `192.168.56.101`

\- Kali attacker: `192.168.56.103`



\## Splunk Setup

Splunk Enterprise was installed on the Windows VM and used as the SIEM platform.



Important observations:

\- Splunk web interface available on port `8000`

\- Splunk management port `8089` visible during scanning



\## Sysmon Setup

Sysmon was installed and the service was confirmed running.



Validation example:

```cmd

sc query sysmon64

