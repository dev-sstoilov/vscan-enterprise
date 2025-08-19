# 🔒 Enterprise Vulnerability Scanner v2.6

A **security-focused vulnerability scanner** that integrates with the **Shodan API** and leverages **DNS-over-TLS encryption** to provide enterprise-grade security reporting.  
This tool is designed for **legitimate security research, penetration testing (with permission), and enterprise IT auditing**.  

⚠️ **Disclaimer:** This tool must only be used on systems and networks you own or have explicit permission to test. Unauthorized scanning is illegal and punishable under computer crime laws.

---

## ✨ Features

- **DNS-over-TLS Encryption** (via Cloudflare 1.1.1.1)  
- **Direct Shodan API Integration** for host intelligence  
- **Enterprise-Grade Reporting** (with CVSS, vulnerabilities, banners, and recommendations)  
- **Automatic API Key Verification & Config Saving**  
- **Security-Focused Implementation** (no AV triggers, clean requests)  
- **Cross-Platform Support** (Windows/Linux/macOS)

---

## 📦 Installation

1. Clone the repository:

```bash
git clone https://github.com/dev-sstoilov/vscan.git
cd vscan
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `requests`
- `dnspython`

---

## ⚙️ Configuration

The scanner will automatically create a `vscan_config.json` file after the first run.  
You may also manually create one with the following structure:

```json
{
  "shodan_key": "YOUR_SHODAN_API_KEY"
}
```

---

## 🚀 Usage

Run the scanner:

```bash
python vscan.py
```

You will be prompted for:

- **Target IP Address**
- **Shodan API Key** (if not already saved in `vscan_config.json`)

---

## 📊 Example Output

```
============================================================
    ██╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗██████╗ ███████╗
    ██║   ██║██║   ██║██║  ██║██║   ██║██╔══██╗██╔════╝
    ██║   ██║██║   ██║███████║██║   ██║██████╔╝███████╗
    ╚██╗ ██╔╝██║   ██║██╔══██║██║   ██║██╔══██╗╚════██║
     ╚████╔╝ ╚██████╔╝██║  ██║╚██████╔╝██████╔╝███████║
      ╚═══╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝

    Enterprise Vulnerability Scanner v2.6
------------------------------------------------------------
```

A report is generated in the format:

```
vscan_report_YYYYMMDD_HHMMSS.txt
```

### Example Report Snippet:
```
Vulnerability Scan Report
==================================================
Target IP: 93.184.216.34
Scan Date: 2025-08-19 14:00:00
Anonymization: DNS-over-TLS Encryption

Organization: Example Org
Operating System: Linux 4.x
Hostnames: example.com
Open Ports: 5

Detected Vulnerabilities:
--------------------------------------------------
1. CVE-2021-12345 (CVSS: 7.8)
Remote Code Execution vulnerability affecting Apache servers.

Exposed Services:
--------------------------------------------------
1. Port 80: Apache httpd 2.4.29
   Banner: Apache/2.4.29 (Ubuntu) OpenSSL/1.1.1...
```

---

## 🛡️ Security Advisory

- Only use this tool on networks **you own or are authorized to test**.  
- Unauthorized use may result in **legal consequences**.  
- Regularly **update your Shodan API key permissions** and verify access.  
- Combine with other auditing practices for **comprehensive security monitoring**.  

---

## 📜 License

MIT License – free to use, modify, and distribute. Attribution is appreciated.  

---

## 👨‍💻 Author

Developed by **Stefan Nikolay Stoilov**  
For professional security assessments, enterprise auditing, and ethical penetration testing.  
