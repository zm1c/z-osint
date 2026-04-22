<h1 align="center">༒ Z-OSINT ༒</h1>

<p align="center">
  <b>Advanced Reconnaissance & Email Intelligence Framework</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Security-OSINT-magenta?style=flat-square" alt="OSINT">
  <img src="https://img.shields.io/badge/License-MIT-white?style=flat-square" alt="License">
</p>

<p align="center">
  <img src="img/tool.png" alt="Z-OSINT Dashboard" width="850"/>
</p>

---

## 𖣘  Overview
**Z-OSINT** is a modular intelligence tool designed for security auditors and SOC analysts. It automates the process of identity inference and corporate reconnaissance starting from a single email address, integrating multiple data sources to identify infrastructure vulnerabilities and account exposure.

## 𖣘  Core Modules

### ⇝ Identity Profiling
*   **Name Inference:** Algorithmic prefix deconstruction for real-name identification.
*   **Gravatar API:** Automated extraction of high-resolution profile imagery and user data.
*   **LinkedIn Dorking:** Automated generation of precise search queries for corporate role identification.

### ⇝ Corporate Reconnaissance
*   **Infra Audit:** Real-time analysis of **SPF and DMARC** policies to assess spoofing and BEC risks.
*   **WHOIS Forensics:** Automated domain registrar auditing and expiration tracking.
*   **Organization Discovery:** Intelligent TLD deconstruction and web scraping for entity identification.

### ⇝ External Intelligence
*   **Service Enumeration:** Deep integration with `Holehe` to map accounts across 120+ platforms.
*   **Threat Intel:** Real-time infection check (Infostealer Logs) via `HudsonRock`.
*   **Data Breach Audit:** Massive exposure analysis using `LeakCheck` repositories.


## 𖣘  Installation

**Clone the repository:**
```bash
git clone https://github.com/zm1c/z-osint.git
cd z-osint
```

## 𖣘  System Requirements:

Ensure the whois package is available on your Linux system:
```bash
sudo apt update && sudo apt install whois -y
```

## 𖣘  Deploy Dependencies:
```bash
pip install -r requirements.txt
```

## 𖣘  Usage

**Single Target**
```bash
python3 z-osint.py target@company.com
```

**Bulk Mode:**
Create a targets.txt file with one email per line and run:
```bash
python3 z-osint.py targets.txt
```

## ⚠️ Disclaimer
This tool is intended for educational purposes and authorized professional security testing only. Use of this tool against targets without prior written consent is illegal. The author assumes no liability for any misuse or damage caused by this program.

<p align="center">
Developed with 💜 by <b>zm1c</b>
</p>
