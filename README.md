# AI Security Log Analyzer

---

## Overview

This project is a Python-based security investigation tool that analyses multiple log files to detect suspicious activity. It automates tasks typically performed manually by security analysts.

## Features

* Brute force login detection
* Suspicious PowerShell command detection
* Indicator of Compromise (IOC) matching
* Abnormal web traffic detection

## Architecture

The system follows a modular design:

* Each detection runs in a separate Python script
* A central script (`main.py`) orchestrates execution
* Results are combined into a structured investigation report

## How It Works

The tool processes multiple log sources:

* Authentication logs → detects brute force attempts
* PowerShell logs → detects suspicious commands
* Web logs → identifies abnormal traffic
* IOC list → matches known malicious indicators

## How to Run

Run using PowerShell:

```
.\run.ps1
```

## Technologies Used

* Python
* PowerShell
* Log analysis techniques

## Example Output

The tool generates a structured report highlighting suspicious IP addresses, commands, and activity patterns.

## Why I Built This

This project was developed to automate security investigations and demonstrate practical scripting and log analysis skills in cybersecurity.
