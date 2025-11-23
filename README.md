# 🛡️ Interactive Network Security Scanner

<div align="center">

![MIT License](https://img.shields.io/badge/License-MIT-green.svg)
![Python Version](https://img.shields.io/badge/Python-3.6%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Maintenance](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)

</div>

## 🚀 Overview

A **powerful, professional-grade** network security scanner built with Python, designed for system administrators, cybersecurity professionals, and penetration testers. This tool combines ease of use with advanced features like automatic local IP detection, multithreaded scanning, real-time vulnerability assessment, and comprehensive reporting—all wrapped in an intuitive, menu-driven terminal interface.

**Author:** Madhav Garg

---

## ✨ Key Highlights

- 🎯 **Zero Dependencies** - Built entirely with Python standard library
- ⚡ **Lightning Fast** - Multithreaded architecture with configurable thread pools (50-500 threads)
- 🔐 **Security-Focused** - Built-in vulnerability assessment and risk categorization
- 📊 **Professional Reports** - Export detailed JSON reports with all findings
- 🎨 **Beautiful UI** - Clean, intuitive terminal interface with helpful prompts
- 🌐 **Network Intelligence** - Automatic network discovery and gateway detection

---

## 🎯 Features

### Core Scanning Capabilities
- 🔍 **Quick Scan** - Rapid assessment of common ports (1-1024)
- 🔎 **Full Scan** - Comprehensive scan of all 65,535 ports
- ⚙️ **Custom Scan** - Flexible user-defined port ranges for targeted assessments
- 🌐 **Local Network Scan** - Discover and scan devices on your local network

### Advanced Features
- 📊 **Vulnerability Assessment** - Intelligent risk categorization (Critical, High, Medium, Low)
- 🏷️ **Banner Grabbing** - Extract service version information from HTTP/S, SMTP, and more
- 🔒 **SSL/TLS Analysis** - Certificate validation and cipher suite detection
- 🌐 **Network Intelligence** - Automatic local IP detection and gateway identification
- 📋 **Multithreaded Engine** - Configurable thread pools for optimal performance
- 💾 **JSON Export** - Comprehensive scan reports with vulnerability details
- ⚙️ **Configurable Settings** - Customize thread count, timeouts, and scan parameters
- 📖 **Built-in Documentation** - Comprehensive help and usage guides

---

## 🛠️ Installation

### Prerequisites
- **Python 3.6+** (Python 3.8 or higher recommended)
- No external dependencies required!

### Quick Start

1. **Clone the Repository**

    ```bash
    git clone (https://github.com/Flash1285/Network_Scanner.git)
    cd Network_Scanner
    ```

2. **Verify Python Installation**

    ```bash
    python3 --version
    ```

3. **Run the Scanner**

    ```bash
    python3 nsc.py
    ```

### Standard Library Dependencies
All required modules are part of Python's standard library:
- `socket` - Network communication
- `threading` - Concurrent scanning
- `json` - Report generation
- `ssl` - SSL/TLS analysis
- `datetime` - Timestamp management
- `subprocess` - System commands
- `os` - File system operations
- `re` - Pattern matching
- `concurrent.futures` - Thread pool management

*No pip install needed!*

---

## 🖥️ Usage

### Interactive Menu

Launch the scanner and navigate through the intuitive menu:

```bash
python3 nsc.py
```

### Main Menu Options

```
╔══════════════════════════════════════════════════════════════╗
║ 🛡️ NETWORK SECURITY SCANNER 🛡️                              ║
║ Professional Security Assessment Tool                        ║
╚══════════════════════════════════════════════════════════════╝

1. 🔍 Quick Scan (Ports 1-1024)
2. 🔎 Full Scan (Ports 1-65535)
3. ⚙️ Custom Scan (Choose Range)
4. 🌐 Scan Local Network
5. 📊 View Network Info
6. ⚙️ Settings
7. 📖 Help
8. 🚪 Exit
```

### Common Workflows

**Quick Security Assessment:**
1. Select option `1` (Quick Scan)
2. Enter target IP or hostname
3. Review open ports and vulnerabilities
4. Export results to JSON if needed

**Comprehensive Audit:**
1. Select option `2` (Full Scan)
2. Enter target IP or hostname
3. Wait for complete port enumeration
4. Analyze vulnerability report
5. Export detailed findings

**Targeted Investigation:**
1. Select option `3` (Custom Scan)
2. Specify port range (e.g., 80-443)
3. Review specific service exposure

---

## 📊 Sample Output

### Terminal Output
```
[+] Scanning 192.168.1.100...
[+] Open Ports Found:
    Port 22   - SSH (OpenSSH 8.2)
    Port 80   - HTTP
    Port 443  - HTTPS (TLS 1.3)

[!] Vulnerability Assessment:
    🔴 CRITICAL: Port 22 - Outdated SSH version detected
    🟡 MEDIUM: Port 80 - Unencrypted HTTP service
```

### JSON Report Structure
```json
{
  "scan_time": "2025-11-23T11:08:02",
  "target": "192.168.1.100",
  "open_ports": [
    {
      "port": 22,
      "service": "SSH",
      "banner": "OpenSSH 8.2",
      "risk_level": "CRITICAL"
    }
  ],
  "vulnerabilities": [...],
  "summary": {...}
}
```

---

## 🔒 Security Concepts & Learning

This tool demonstrates essential cybersecurity concepts:

### Network Reconnaissance
- **Port Scanning** - Identifying open ports and services on target systems
- **Service Enumeration** - Discovering what applications are running
- **Attack Surface Mapping** - Understanding potential entry points

### Vulnerability Assessment
- **Risk Categorization** - Classifying threats by severity
- **Service Fingerprinting** - Identifying software versions
- **Configuration Analysis** - Detecting misconfigurations

### Technical Skills
- **Banner Grabbing** - Extracting service version information
- **SSL/TLS Analysis** - Evaluating encryption implementations
- **Multithreading** - Efficient parallel processing
- **Network Protocols** - Understanding TCP/IP communication

---

## 🧩 Best Practices & Tips

### Performance Optimization
- 🚀 **Thread Count** - Start with 100 threads, increase for faster scans
- 🎯 **Targeted Scans** - Use custom ranges instead of full scans when possible
- ⏱️ **Timeout Settings** - Adjust based on network latency

### Security Considerations
- ⚠️ **Authorization Required** - Only scan networks/systems you own or have permission to test
- 🔒 **Legal Compliance** - Unauthorized scanning is illegal in most jurisdictions
- 📝 **Documentation** - Keep records of scan permissions and findings
- 🛡️ **Responsible Disclosure** - Report vulnerabilities through proper channels

### Testing Recommendations
- 🧪 **Safe Testing** - Use `scanme.nmap.org` for practice
- 🏠 **Local Network** - Start with your own devices
- 📊 **Baseline Scans** - Regular scans to track changes over time
- 🔄 **Follow-up Tools** - Use Nessus, OpenVAS, or Metasploit for deeper analysis

---

## 🐛 Troubleshooting

### Common Issues

**Issue:** "Permission denied" errors
- **Solution:** Run with appropriate permissions (may need sudo on Linux/macOS)

**Issue:** Slow scan performance
- **Solution:** Increase thread count in Settings menu

**Issue:** No open ports detected
- **Solution:** Verify target is reachable (ping test) and firewall settings

**Issue:** Connection timeouts
- **Solution:** Increase timeout value in Settings or check network connectivity

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. 🍴 Fork the repository
2. 🌟 Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. 💻 Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. 📤 Push to the branch (`git push origin feature/AmazingFeature`)
5. 🔃 Open a Pull Request

---

## 📸 Screenshots

*Screenshots demonstrating the tool in action can be found in the `Screenshots` directory.*

---

## ❗ Legal & Ethical Notice

> [!WARNING]
> **IMPORTANT:** This tool is provided for educational and authorized security testing purposes only.

### Legal Requirements
- ✅ **Only scan systems you own** or have explicit written permission to test
- ❌ **Unauthorized scanning is illegal** and may violate computer fraud laws
- 📋 **Obtain proper authorization** before any security assessment
- 🔒 **Respect privacy** and confidentiality of discovered information

### Ethical Guidelines
- Use this tool responsibly and ethically
- Follow responsible disclosure practices
- Respect network resources and bandwidth
- Do not use for malicious purposes

**The author assumes no liability for misuse of this tool.**

---

## 👤 Author

**Madhav Garg**
- 📧 Email: ujjwalshield@gmail.com
- 🎓 Cybersecurity Student & Enthusiast
- 🔗 TryHackMe: [https://tryhackme.com/p/UJz](https://tryhackme.com/p/UJz)
- 💼 Passionate about network security and ethical hacking

---

## 📂 Repository Structure

```
Network_Scanner/
├── nsc.py                       # Main Scanner Script (Core Application)
├── demo_scan_report.json        # Sample Scan Report
├── README.md                    # Documentation (This File)
├── Screenshots/                 # Demo Images & Examples
└── LICENSE                      # MIT License
```

---

## 🗺️ Roadmap

Future enhancements planned:

- [ ] OS Detection capabilities
- [ ] Service version detection improvements
- [ ] CVE database integration
- [ ] Web-based dashboard
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] Database storage for historical scans
- [ ] API endpoints for automation

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License - Copyright (c) 2025 Madhav Garg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

- Inspired by industry-standard tools like Nmap and Masscan
- Built with Python's powerful standard library
- Thanks to the cybersecurity community for continuous learning resources

---

## 📞 Support

If you encounter any issues or have questions:

1. 📖 Check the built-in Help menu
2. 🐛 Open an issue on GitHub
3. 📧 Contact the author
4. 💬 Join cybersecurity communities for discussions

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

Made with ❤️ by Madhav Garg

</div>
