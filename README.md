# Security Investigation & Log Analysis Toolkit

A Python-based security investigation toolkit designed to analyse multiple sources of security-related data and identify suspicious activity.

## Overview

This project demonstrates practical security scripting and investigation techniques by analysing:

- Authentication activity
- Process execution logs
- Registry persistence indicators
- Suspicious files
- Indicators of Compromise (IOCs)
- PowerShell activity
- Abnormal web traffic

The toolkit uses modular analysis scripts and produces structured investigation findings and risk assessments.

## Detection Capabilities

### Authentication Analysis
Identifies repeated failed authentication attempts and highlights suspicious IP addresses based on configurable thresholds.

### PowerShell Analysis
Detects suspicious PowerShell activity including:

- Encoded commands
- Execution policy bypass
- `Invoke-WebRequest`
- `DownloadString`

Base64-encoded PowerShell commands can also be decoded for investigation.

### IOC Detection
Matches known indicators such as IP addresses and URLs against log data and records the relevant file, line number and surrounding context.

### File & Persistence Analysis
Examines suspicious files and registry run-key data to identify potential persistence mechanisms.

### Process Log Analysis
Analyses process execution logs for suspicious activity and generates investigation alerts.

## Architecture

The project follows a modular approach:

```text
Security Investigation Toolkit
│
├── Log Analysis
│   ├── Authentication
│   ├── PowerShell
│   ├── IOC Matching
│   └── Web/Access Activity
│
├── Forensic Analysis
│   ├── Suspicious Files
│   ├── Registry Persistence
│   └── Process Execution
│
└── Investigation Report
