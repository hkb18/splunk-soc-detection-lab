# Nmap Port Scan Attack Simulation

## Objective

Simulate reconnaissance activity from an attacker system and generate telemetry that can be detected in Splunk.

---

## Attacker System

- Kali Linux
- Tool: Nmap

---

## Target System

- Windows 10 FLARE VM
- Target IP: `192.168.56.101`

---

## Attack Execution

A TCP connect scan was executed from the Kali attacker machine.

Command used:

nmap -sT -p- 192.168.56.101

This scan attempts to connect to every TCP port on the target system.

nmap -sT 192.168.56.101

nmap -sS 192.168.56.101

The purpose of these scans was to enumerate open ports and running services.

---

## Scan Evidence

![Kali Nmap Scan](../screenshots/08_Kali_Nmap_Port_Scan.png)

The scan identified several open ports including:

- 135
- 139
- 445
- 5040
- 7680
- 8000
- 8089
- 8191
- 49664–49670

Ports `8000` and `8089` correspond to Splunk services running on the Windows host.

This scan generates network connection telemetry that can later be analyzed in Splunk for detection engineering.


## Log Source Used For Detection

Two log sources were available in the lab:

Sysmon logs  
Windows Security logs

Initial detection attempts used Sysmon Event ID 3 (network connection events). However the active Sysmon configuration did not produce useful external network telemetry.

The working detection source became Windows Security Event ID 5156.

Event 5156 records network connections allowed through the Windows Filtering Platform.

## Detection Logic

The detection identifies a host contacting many different destination ports in a short time window.

Fields extracted:

SourceAddress  
DestPort

If a host connects to many unique ports in a short time window, it likely indicates port scanning activity.

## Splunk Detection Query

index=main sourcetype="XmlWinEventLog:Security"
| rex "<EventID>(?<event_id>\d+)</EventID>"
| search event_id=5156
| rex field=_raw "<Data Name='SourceAddress'>(?<SourceAddress>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestPort'>(?<DestPort>[^<]+)</Data>"
| bin _time span=1m
| stats dc(DestPort) as scanned_ports by SourceAddress _time
| where scanned_ports > 10
| sort - scanned_ports

## Detection Result

The query identified the attacker host:

192.168.56.103

The host contacted 15 different ports within the same time bucket.

This matched the Nmap scan activity generated from the Kali machine.

## MITRE ATT&CK Mapping

Tactic  
Reconnaissance

Technique  
T1046 – Network Service Discovery

## Analyst Notes

This lab demonstrates a basic SOC workflow:

1. simulate attacker behaviour  
2. confirm telemetry availability  
3. extract useful fields from logs  
4. build detection logic  
5. validate detection results against attacker activity