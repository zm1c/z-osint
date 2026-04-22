<h1 align="center">💜 Z-OSINT</h1>

<p align="center">
  <b>Advanced Reconnaissance & Threat Intelligence System</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Status-Elite_Intelligence-magenta?style=for-the-badge" alt="OSINT">
  <img src="https://img.shields.io/badge/License-MIT-white?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="img/tool.png" alt="Z-OSINT Dashboard" width="800"/>
</p>

---

## 🎯 Overview

**Z-OSINT** is a professional-grade Open Source Intelligence (OSINT) suite designed for high-stakes cybersecurity operations. Engineered for auditors, SOC analysts, and Red Teamers, this system moves beyond simple scanning by integrating **automated corporate reconnaissance** and **identity inference** to transform a single email into a tactical intelligence asset.

---

## 🚀 Key Intelligence Modules

### 👤 Identity Intelligence
- **Smart Name Inference:** Sophisticated algorithm that deconstructs email prefixes (e.g., `apalmal` ➔ `A. Palma`) to identify real targets.
- **LinkedIn Smart Dorking:** Automated generation of surgical search queries cross-referencing deduced names with real-time corporate data.
- **Visual Profiling:** Real-time identity discovery via Gravatar to extract names and high-resolution profile imagery.

### 🛡️ Corporate Reconnaissance (Recon)
- **Auto-Organization Identification:** Tactical recognition of companies via *Web Scraping* of official titles and intelligent TLD deconstruction (supporting `.edu.pe`, `.com.mx`, `.org.uk`, etc.).
- **Infrastructure Audit:** Real-time analysis of **SPF and DMARC** policies to identify Critical Spoofing vulnerabilities and BEC (Business Email Compromise) risks.
- **WHOIS Forensics:** Automated identification of domain registrars and expiration auditing with advanced "Data Redacted" filtering.

### 🔍 Global Intelligence Engines
- **Service Enumeration:** Seamless integration with `Holehe` to map presence across 120+ global platforms (Office365, Twitter/X, LinkedIn, etc.).
- **Threat Intel:** Direct verification of malware infections (Infostealer Logs) through `HudsonRock` integration.
- **Exposure Analysis:** Massive data breach auditing via `LeakCheck` repositories.

---

## 🛡️ Stealth & Professional Design

- **Rich Dashboard UI:** High-definition terminal interface for immediate intelligence consumption.
- **Stealth Batch Processing:** Massive recon capability with randomized delay algorithms to evade WAFs and Rate-Limits.
- **Minimalist CLI:** Clean, professional interface designed for seamless operation in SIEM/SOC environments.

---

## Installation

**Clone the repository:**
```bash
git clone https://github.com/zm1c/z-osint.git
cd z-osint
```

## System Requirements:

Ensure the whois package is available on your Linux system:
```bash
sudo apt update && sudo apt install whois -y
```

## Deploy Dependencies:
```bash
pip install -r requirements.txt
```

## 🔥 Usage

**Analyze a single target:**
```bash
python3 z-osint.py target@company.com
```

**Batch Mode (Bulk Scan):**
Create a targets.txt file with one email per line and run:
```bash
python3 z-osint.py targets.txt
```

## Reporting
Z-OSINT generates an immediate visual report on the dashboard and exports a structured JSON log for every target. These reports are ready for ingestion into SIEM platforms, data lakes, or for inclusion in formal security audit documentation.

## ⚠️ Disclaimer
This tool is intended for educational purposes and authorized professional security testing only. Use of this tool against targets without prior written consent is illegal. The author assumes no liability for any misuse or damage caused by this program.

<p align="center">
Developed with ❤️ by <b>zm1c</b>
</p>
```
