# \# Splunk SOC Detection Lab

# 

# This project demonstrates how to build a small Security Operations Center (SOC) detection lab using Splunk, Sysmon, and a simulated attacker environment.

# 

# The lab collects telemetry from a Windows endpoint, simulates attacker activity, and demonstrates how suspicious behavior can be identified using Splunk queries.

# 

# ------------------------------------------------------------

# 

# Lab Overview

# 

# Architecture used in this lab:

# 

# \- Windows 10 FLARE VM (Target System)

# \- Kali Linux VM (Attacker)

# \- Splunk Enterprise 10.2.1 (SIEM Platform)

# \- Sysmon (Endpoint Telemetry Collection)

# \- Oracle VirtualBox (Virtualization Platform)

# 

# The objective is to simulate attacker reconnaissance activity and detect it using Splunk.

# 

# ------------------------------------------------------------

# 

# Splunk Platform

# 

# Splunk Enterprise was installed on the Windows target VM to collect and analyze security telemetry.

# 

# Splunk Login

# 

# !\[Splunk Login](screenshots/01\_Splunk\_Login\_Page.png)

# 

# Splunk Dashboard

# 

# !\[Splunk Dashboard](screenshots/02\_Splunk\_Dashboard\_Home.png)

# 

# Splunk Version

# 

# !\[Splunk Version](screenshots/03\_Splunk\_Enterprise\_Version.png)

# 

# ------------------------------------------------------------

# 

# Sysmon Telemetry

# 

# Sysmon was deployed to enhance Windows logging capabilities and provide detailed endpoint telemetry including process activity, network connections, and file creation events.

# 

# Sysmon Logs in Splunk

# 

# !\[Sysmon Logs](screenshots/05\_Sysmon\_Logs\_Ingested\_in\_Splunk.png)

# 

# Sysmon Event Distribution

# 

# !\[Sysmon Event Statistics](screenshots/06\_Sysmon\_EventID\_Statistics.png)

# 

# These logs confirm that endpoint telemetry is successfully being ingested into Splunk.

# 

# ------------------------------------------------------------

# 

# Attack Simulation

# 

# A reconnaissance scan was executed from the Kali Linux attacker VM against the Windows target.

# 

# Command used:

# 

# nmap -sT -p- 192.168.56.101

# 

# This scan attempts to connect to all TCP ports on the target system.

# 

# Nmap Scan Evidence

# 

# !\[Kali Nmap Scan](screenshots/08\_Kali\_Nmap\_Port\_Scan.png)

# 

# ------------------------------------------------------------

# 

# Detection Engineering

# 

# To identify scanning behavior, Windows Security Event ID 5156 was analyzed in Splunk.

# 

# A detection query was created to identify hosts attempting connections to many distinct destination ports within a short time window.

# 

# Detection Query Result

# 

# !\[Port Scan Detection](screenshots/09\_Splunk\_Port\_Scan\_Detection.png)

# 

# Time-Based Correlation

# 

# !\[Time Based Detection](screenshots/11\_Time\_Based\_Port\_Scan\_Detection.png)

# 

# Final Detection Result

# 

# !\[Final Detection Result](screenshots/12\_Final\_Port\_Scan\_Detection\_Result.png)

# 

# The detection successfully identified host:

# 

# 192.168.56.103

# 

# as performing port scanning activity against the Windows target system.

# 

# ------------------------------------------------------------

# 

# Repository Structure

# 

# splunk-soc-detection-lab

# │

# ├─ README.md

# ├─ documentation

# │   └─ lab-setup.md

# ├─ attack-simulation

# │   └─ nmap-scan.md

# ├─ queries

# │   └─ port-scan-detection.spl

# └─ screenshots

# 

# ------------------------------------------------------------

# 

# MITRE ATT\&CK Mapping

# 

# Tactic: Reconnaissance  

# Technique: T1046 – Network Service Discovery

# 

# ------------------------------------------------------------

# 

# Outcome

# 

# This lab demonstrates how endpoint telemetry can be collected, analyzed, and used to detect reconnaissance behavior using Splunk SIEM.

# 

# The project highlights the process of:

# 

# \- Deploying endpoint telemetry

# \- Collecting logs in a SIEM platform

# \- Simulating attacker activity

# \- Building detection logic to identify malicious behavior

