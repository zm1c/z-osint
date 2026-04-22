<h1 align="center">🚀 Z-OSINT PRO v5.2</h1>

<p align="center">
  <b>Advanced Enterprise Intelligence & Corporate Reconnaissance Engine</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/OSINT-Professional-red?style=for-the-badge" alt="OSINT">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="img/tool.png" alt="Z-OSINT PRO Dashboard" width="800"/>
</p>

---

## 🎯 Overview

**Z-OSINT PRO** is an advanced Open Source Intelligence (OSINT) suite designed for cybersecurity auditors, SOC analysts, and Red Teamers. Unlike traditional scanners, this engine combines **DNS infrastructure analysis**, **automated corporate reconnaissance**, and **intelligent identity inference** to transform a simple email address into a comprehensive intelligence profile.

---

## 🚀 Key Features

### 🧠 Identity Intelligence Layer
- **Smart Name Inference:** Deconstructs complex email prefixes (e.g., `apalmal` ➔ `A. Palma`) to deduce real identities.
- **LinkedIn Smart Dorking:** Generates surgical LinkedIn searches by cross-referencing deduced names with identified corporate entities.
- **Identity Discovery:** Gravatar integration to extract real names and profile photographs.

### 🏢 Corporate Reconnaissance (Recon)
- **Auto-Company Recognition:** Identifies the organization through *Web Scraping* of the official site and advanced TLD cleaning (supporting `.edu.pe`, `.com.mx`, `.org.uk`, etc.).
- **DNS Security Audit:** Real-time analysis of **SPF and DMARC** records to determine vulnerability to *Email Spoofing* and *BEC attacks*.
- **Infrastructure WHOIS:** Automated identification of registrars and GDPR privacy audit.

### 🔍 Global Search Engines
- **Service Enumeration:** Powered by `Holehe` to identify account presence across 120+ platforms (Office365, Twitter/X, etc.).
- **Threat Intelligence:** Cross-checks for malware-related compromises (Infostealers) via `HudsonRock`.
- **Data Breach Analysis:** Queries massive data breach repositories via `LeakCheck`.

### 🛡️ Stealth Operations
- **Batch Processing:** Support for massive reconnaissance via `.txt` target lists.
- **Anti Rate-Limit:** Randomized delay algorithm to prevent IP banning from WHOIS and search engines.
- **User-Agent Rotation:** Mimics real-world browser fingerprints to evade basic security detections.

---

## 🛠️ Installation

**Clone the repository:**
```bash
git clone https://github.com/zm1c/email-osint.git
cd email-osint
```
## System Requirements:

Ensure you have the whois system package installed on your Linux machine:
```bash
sudo apt install whois
```

## 📦 Install dependencies:

```bash
pip install -r requirements.txt
```

## 🔥 Usage

**Analyze a single target:**
```bash
python3 z-osint-pro.py target@company.com
```

**Batch Mode (Bulk Scan):**
Create a targets.txt file with one email per line and run:
```bash
python3 z-osint-pro.py targets.txt
```

## Reporting
The tool generates a high-definition visual Dashboard in the terminal using the Rich library. Simultaneously, it exports a structured JSON report for deeper analysis or integration into SIEM platforms like Wazuh.

## ⚠️ Disclaimer
This tool is intended for educational purposes and authorized professional security testing only. Use of this tool against targets without prior written consent is illegal. The author assumes no liability for any misuse or damage caused by this program.

<p align="center">
Developed with ❤️ by <b>zm1c</b>
</p>
```
