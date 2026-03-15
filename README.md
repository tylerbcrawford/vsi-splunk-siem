![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-0078D6?style=flat&logo=windows&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-D22128?style=flat&logo=apache&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat&logo=ubuntu&logoColor=white)

# VSI Splunk SIEM

Custom SIEM built in Splunk for a fictional company (Virtual Space Industries). Team of three acting as SOC analysts, UofT cybersecurity program (2024).

## The Setup

We ingested logs from a Windows Server and an Apache web server into Splunk, built dashboards and alerts, then had simulated attacks thrown at us to see if our detection rules would catch them.

## What We Built

- **Baseline reports** — established normal traffic patterns first (peak hours, typical HTTP methods, geographic distribution) so we'd actually know when something looked wrong
- **Custom alerts** — brute-force login detection on the Windows server (threshold: 5 failed logins in 10 minutes), SQL injection pattern matching on Apache, and a volumetric DoS alert based on request rate anomalies
- **Attack dashboards** — real-time panels showing failed auth attempts by source IP, HTTP response code distribution, and geographic heat maps of suspicious traffic

## What We Caught

The simulated attacks hit both servers. Our Splunk alerts fired on the brute-force attempts and the SQLi payloads. The DoS detection worked but needed threshold tuning — the initial alert was too sensitive and would have generated noise in production. We documented the false positive analysis and adjusted the thresholds in our recommendations.

## Tools

Splunk Enterprise, Windows Server 2019, Ubuntu Server (Apache), Wireshark, Python

## Report

Full SIEM implementation report with dashboard screenshots and detection analysis: **[SIEM Implementation Report (PDF)](SIEM_Implementation_Report.pdf)**

## Context

SOC analyst simulation project for UofT's cybersecurity certificate program.
