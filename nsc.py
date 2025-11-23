#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive Network Security Scanner
Author: Madhav Garg
Description: Menu-driven network scanner with automatic IP detection
"""

import socket
import threading
import json
import ssl
import datetime
import subprocess
import re
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

class InteractiveNetworkScanner:
    def __init__(self):
        self.target = None
        self.port_range = (1, 1024)
        self.threads = 100
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Vulnerable services database
        self.vulnerable_services = {
            21: {"service": "FTP", "risk": "HIGH", "issue": "Unencrypted file transfer"},
            23: {"service": "Telnet", "risk": "CRITICAL", "issue": "Unencrypted remote access"},
            25: {"service": "SMTP", "risk": "MEDIUM", "issue": "Potential open relay"},
            53: {"service": "DNS", "risk": "MEDIUM", "issue": "DNS amplification attacks"},
            80: {"service": "HTTP", "risk": "MEDIUM", "issue": "Unencrypted web traffic"},
            110: {"service": "POP3", "risk": "HIGH", "issue": "Unencrypted email retrieval"},
            139: {"service": "NetBIOS", "risk": "HIGH", "issue": "SMB vulnerabilities"},
            143: {"service": "IMAP", "risk": "HIGH", "issue": "Unencrypted email access"},
            445: {"service": "SMB", "risk": "CRITICAL", "issue": "EternalBlue vulnerability"},
            3306: {"service": "MySQL", "risk": "HIGH", "issue": "Database exposure"},
            3389: {"service": "RDP", "risk": "HIGH", "issue": "Remote desktop exposure"},
            5432: {"service": "PostgreSQL", "risk": "HIGH", "issue": "Database exposure"},
            6379: {"service": "Redis", "risk": "CRITICAL", "issue": "Unauthenticated access"},
            27017: {"service": "MongoDB", "risk": "CRITICAL", "issue": "NoSQL injection risk"}
        }
    
    def get_local_ip(self) -> str:
        """Get local machine IP address"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_interfaces(self) -> List[str]:
        """Get all network interfaces and their IPs"""
        interfaces = []
        try:
            hostname = socket.gethostname()
            interfaces.append(f"Hostname: {hostname}")
            
            # Get all IPs associated with hostname
            ips = socket.gethostbyname_ex(hostname)[2]
            for ip in ips:
                interfaces.append(f"IP: {ip}")
            
            # Get local IP
            local_ip = self.get_local_ip()
            if local_ip not in ips:
                interfaces.append(f"Primary IP: {local_ip}")
        except Exception as e:
            interfaces.append(f"Error detecting interfaces: {e}")
        
        return interfaces
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Print application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║               🛡️  NETWORK SECURITY SCANNER 🛡️               ║
║                                                              ║
║              Professional Security Assessment Tool           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_menu(self):
        """Print main menu"""
        print("\n" + "="*60)
        print("                    MAIN MENU")
        print("="*60)
        print("\n[1] 🔍 Quick Scan (Common Ports 1-1024)")
        print("[2] 🔎 Full Scan (All Ports 1-65535)")
        print("[3] ⚙️  Custom Scan (Choose Port Range)")
        print("[4] 🌐 Scan Local Network")
        print("[5] 📊 View Network Information")
        print("[6] ⚙️  Settings")
        print("[7] 📖 Help")
        print("[8] 🚪 Exit")
        print("\n" + "="*60)
    
    def show_network_info(self):
        """Display network information"""
        self.clear_screen()
        self.print_banner()
        print("\n" + "="*60)
        print("           NETWORK INFORMATION")
        print("="*60 + "\n")
        
        interfaces = self.get_network_interfaces()
        for interface in interfaces:
            print(f"  {interface}")
        
        print(f"\n  Default Gateway: {self.get_local_ip()}")
        
        input("\n\nPress Enter to continue...")
    
    def settings_menu(self):
        """Settings configuration"""
        while True:
            self.clear_screen()
            self.print_banner()
            print("\n" + "="*60)
            print("                   SETTINGS")
            print("="*60)
            print(f"\n[1] Thread Count: {self.threads}")
            print(f"[2] Default Port Range: {self.port_range[0]}-{self.port_range[1]}")
            print("[3] Back to Main Menu")
            print("\n" + "="*60)
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                try:
                    threads = int(input("\nEnter thread count (50-500): "))
                    if 50 <= threads <= 500:
                        self.threads = threads
                        print(f"✅ Thread count set to {threads}")
                    else:
                        print("❌ Invalid range. Using default.")
                except ValueError:
                    print("❌ Invalid input.")
                input("\nPress Enter to continue...")
            
            elif choice == "2":
                try:
                    start = int(input("Enter start port: "))
                    end = int(input("Enter end port: "))
                    if 1 <= start <= end <= 65535:
                        self.port_range = (start, end)
                        print(f"✅ Port range set to {start}-{end}")
                    else:
                        print("❌ Invalid range.")
                except ValueError:
                    print("❌ Invalid input.")
                input("\nPress Enter to continue...")
            
            elif choice == "3":
                break
    
    def show_help(self):
        """Display help information"""
        self.clear_screen()
        self.print_banner()
        print("\n" + "="*60)
        print("                     HELP")
        print("="*60 + "\n")
        
        help_text = """
📖 HOW TO USE:

1. QUICK SCAN:
   - Scans common ports (1-1024)
   - Fast and efficient
   - Good for initial assessment

2. FULL SCAN:
   - Scans all ports (1-65535)
   - Takes longer but comprehensive
   - Recommended for thorough analysis

3. CUSTOM SCAN:
   - Choose your own port range
   - Flexible scanning options
   - Target specific services

4. LOCAL NETWORK SCAN:
   - Scan devices on your network
   - Discover active hosts
   - Network mapping

5. NETWORK INFORMATION:
   - View your IP addresses
   - Check network interfaces
   - System information

⚠️  LEGAL NOTICE:
   - Only scan networks you own or have permission to test
   - Unauthorized scanning is illegal
   - Use responsibly and ethically

🔒 SECURITY TIPS:
   - Close unnecessary open ports
   - Update services regularly
   - Use encryption (HTTPS, SSH, etc.)
   - Enable firewalls
        """
        print(help_text)
        input("\n\nPress Enter to continue...")
    
    def get_target_input(self) -> str:
        """Get target IP/hostname from user"""
        print("\n" + "="*60)
        print("           TARGET SELECTION")
        print("="*60 + "\n")
        
        local_ip = self.get_local_ip()
        print(f"💡 Your IP: {local_ip}")
        print(f"💡 Localhost: 127.0.0.1")
        print(f"💡 Example: scanme.nmap.org (safe test target)")
        
        target = input("\n🎯 Enter target IP or hostname: ").strip()
        
        if not target:
            print("\n⚠️  No target specified. Using localhost.")
            target = "127.0.0.1"
        
        return target
    
    def resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            print(f"\n✅ Resolved {target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"\n❌ Could not resolve hostname: {target}")
            return None
    
    def scan_port(self, ip: str, port: int) -> Dict:
        """Scan a single port"""
        result = {
            "port": port,
            "state": "closed",
            "service": None,
            "banner": None,
            "ssl_info": None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            connection = sock.connect_ex((ip, port))
            
            if connection == 0:
                result["state"] = "open"
                result["service"] = self.get_service_name(port)
                
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    result["banner"] = banner[:200]
                except:
                    pass
                
                if port in [443, 8443, 993, 995, 465]:
                    result["ssl_info"] = self.check_ssl(ip, port)
                
                self.open_ports.append(port)
                print(f"  [+] Port {port:5d} OPEN  - {result['service']}")
            
            sock.close()
            
        except socket.timeout:
            pass
        except Exception:
            pass
        
        return result
    
    def get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"
    
    def check_ssl(self, ip: str, port: int) -> Dict:
        """Check SSL/TLS certificate information"""
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssl_info["version"] = ssock.version()
                    ssl_info["cipher"] = ssock.cipher()
        except Exception as e:
            ssl_info["error"] = str(e)
        
        return ssl_info
    
    def scan_ports(self, ip: str, port_range: Tuple[int, int]):
        """Scan multiple ports using thread pool"""
        print(f"\n🔍 Scanning {ip} - Ports {port_range[0]}-{port_range[1]}")
        print(f"⚙️  Using {self.threads} threads")
        print(f"⏱️  Started at {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        print("-" * 60)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for port in range(port_range[0], port_range[1] + 1):
                futures.append(executor.submit(self.scan_port, ip, port))
            
            for future in as_completed(futures):
                result = future.result()
                if result["state"] == "open":
                    self.scan_results[result["port"]] = result
        
        print("-" * 60)
    
    def vulnerability_assessment(self):
        """Assess vulnerabilities based on open ports"""
        print("\n\n🔐 VULNERABILITY ASSESSMENT")
        print("=" * 60 + "\n")
        
        if not self.open_ports:
            print("✅ No open ports found - System appears secure")
            return
        
        for port in self.open_ports:
            if port in self.vulnerable_services:
                vuln = self.vulnerable_services[port].copy()
                vuln["port"] = port
                self.vulnerabilities.append(vuln)
                
                risk_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }
                
                icon = risk_icon.get(vuln['risk'], '⚪')
                print(f"{icon} {vuln['risk']:8s} - Port {port:5d} ({vuln['service']:15s}): {vuln['issue']}")
    
    def generate_report(self):
        """Generate and save scan report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.json"
        
        report = {
            "scan_info": {
                "target": self.target,
                "scan_time": datetime.datetime.now().isoformat(),
                "port_range": f"{self.port_range[0]}-{self.port_range[1]}",
                "open_ports_found": len(self.open_ports)
            },
            "open_ports": self.scan_results,
            "vulnerabilities": self.vulnerabilities,
            "risk_summary": {
                "CRITICAL": len([v for v in self.vulnerabilities if v["risk"] == "CRITICAL"]),
                "HIGH": len([v for v in self.vulnerabilities if v["risk"] == "HIGH"]),
                "MEDIUM": len([v for v in self.vulnerabilities if v["risk"] == "MEDIUM"]),
                "LOW": len([v for v in self.vulnerabilities if v["risk"] == "LOW"])
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n\n📄 Report saved: {filename}")
    
    def print_summary(self):
        """Print scan summary"""
        print("\n\n" + "="*60)
        print("                  SCAN SUMMARY")
        print("="*60)
        print(f"\n🎯 Target: {self.target}")
        print(f"📊 Open Ports: {len(self.open_ports)}")
        print(f"⚠️  Vulnerabilities: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\n📈 Risk Breakdown:")
            risk_count = {}
            for vuln in self.vulnerabilities:
                risk = vuln["risk"]
                risk_count[risk] = risk_count.get(risk, 0) + 1
            
            for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if risk in risk_count:
                    print(f"   {risk}: {risk_count[risk]}")
        
        print("="*60)
    
    def perform_scan(self, scan_type: str):
        """Perform network scan"""
        self.clear_screen()
        self.print_banner()
        
        # Reset previous scan data
        self.open_ports = []
        self.scan_results = {}
        self.vulnerabilities = []
        
        # Get target
        self.target = self.get_target_input()
        
        # Resolve target
        ip = self.resolve_target(self.target)
        if not ip:
            input("\n\nPress Enter to continue...")
            return
        
        # Set port range based on scan type
        if scan_type == "quick":
            port_range = (1, 1024)
        elif scan_type == "full":
            port_range = (1, 65535)
            print("\n⚠️  Full scan may take 10-30 minutes...")
            confirm = input("Continue? (y/n): ").strip().lower()
            if confirm != 'y':
                return
        elif scan_type == "custom":
            try:
                start = int(input("\n📍 Start port: "))
                end = int(input("📍 End port: "))
                if 1 <= start <= end <= 65535:
                    port_range = (start, end)
                else:
                    print("❌ Invalid range. Using default.")
                    port_range = (1, 1024)
            except ValueError:
                print("❌ Invalid input. Using default.")
                port_range = (1, 1024)
        
        # Perform scan
        input("\n\n🚀 Press Enter to start scan...")
        self.scan_ports(ip, port_range)
        
        # Vulnerability assessment
        self.vulnerability_assessment()
        
        # Print summary
        self.print_summary()
        
        # Generate report
        save = input("\n\n💾 Save report? (y/n): ").strip().lower()
        if save == 'y':
            self.generate_report()
        
        input("\n\nPress Enter to continue...")
    
    def run(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            choice = input("\n👉 Select option (1-8): ").strip()
            
            if choice == "1":
                self.perform_scan("quick")
            
            elif choice == "2":
                self.perform_scan("full")
            
            elif choice == "3":
                self.perform_scan("custom")
            
            elif choice == "4":
                print("\n🚧 Local network scan - Coming soon!")
                input("\nPress Enter to continue...")
            
            elif choice == "5":
                self.show_network_info()
            
            elif choice == "6":
                self.settings_menu()
            
            elif choice == "7":
                self.show_help()
            
            elif choice == "8":
                self.clear_screen()
                print("\n\n👋 Thank you for using Network Security Scanner!")
                print("🛡️  Stay secure!\n")
                break
            
            else:
                print("\n❌ Invalid option. Please try again.")
                input("\nPress Enter to continue...")


def main():
    """Entry point"""
    try:
        scanner = InteractiveNetworkScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n\n⚠️  Scan interrupted by user")
        print("👋 Goodbye!\n")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")


if __name__ == "__main__":
    main()
