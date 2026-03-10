# Nmap Scan Attack Simulation

## Objective
This lab simulates reconnaissance activity from a Kali Linux attacker machine against a Windows 10 FLARE VM target and demonstrates how the activity can be detected using Splunk.

## Environment

Attacker Machine
Kali Linux VM

Target Machine
Windows 10 FLARE VM

SIEM
Splunk Enterprise 10.2.1

Monitoring
Sysmon

Virtualization
Oracle VirtualBox

Network Mode
Host-only network

Observed IP Addresses

Windows Target: 192.168.56.101
Kali Attacker: 192.168.56.103

## Attack Simulation

First connectivity between Kali and the Windows target was verified.

Command used:

ping 192.168.56.101

Once connectivity was confirmed, an Nmap scan was performed from Kali against the Windows target.

Example command used:

nmap -sS 192.168.56.101

nmap -sT -p- 192.168.56.101

The purpose of these scans was to enumerate open ports and running services.

## Observed Open Ports

The scan discovered the following ports on the Windows target:

135/tcp
139/tcp
445/tcp
8000/tcp
8089/tcp

Port 8000 and 8089 correspond to Splunk services running on the Windows machine.

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
