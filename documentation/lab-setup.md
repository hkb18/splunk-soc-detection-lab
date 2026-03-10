# Lab Setup

## Objective

Build a SOC-style detection engineering lab using Splunk Enterprise, Sysmon, a Windows 10 FLARE VM, and a Kali Linux attacker VM.

The goal of the lab is to generate security telemetry, ingest the logs into Splunk SIEM, simulate attacker behavior, and build detection logic capable of identifying suspicious activity such as port scanning.

---

## Lab Components

### Target System

- Windows 10 FLARE VM
- Splunk Enterprise 10.2.1
- Sysmon
- Windows Event Logs

### Attacker System

- Kali Linux
- Nmap

### Virtualization Platform

- Oracle VirtualBox

---

## Network Design

The lab environment used **VirtualBox host-only networking** to allow communication between the attacker and target systems without exposing the lab to the external network.

Observed addressing during the lab:

- Windows target VM: `192.168.56.101`
- Kali attacker VM: `192.168.56.103`

---

## Splunk Setup

Splunk Enterprise was installed on the Windows 10 FLARE VM and used as the Security Information and Event Management (SIEM) platform for log collection and analysis.

Key details:

- Splunk Enterprise Version: **10.2.1**
- Web interface: `http://localhost:8000`
- Management port: `8089`

The Splunk web interface was successfully accessed through a browser and administrative login was confirmed.

Evidence screenshots:

- `01_Splunk_Login_Page.png`
- `02_Splunk_Dashboard_Home.png`
- `03_Splunk_Enterprise_Version.png`

---

## Sysmon Deployment

Sysmon (System Monitor) from Microsoft Sysinternals was installed on the Windows target system to provide enhanced telemetry for process activity, network connections, file creation, and registry changes.

A configuration file was applied using the following command:

```cmd
Sysmon64.exe -c C:\sysmonconfig.xml