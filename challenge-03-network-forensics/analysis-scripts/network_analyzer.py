#!/usr/bin/env python3
"""
Network Traffic Analysis for CTF Challenge 3
Simulates analysis of a PCAP file containing malicious activity
"""

import json
import base64
from datetime import datetime
import re
import hashlib

class NetworkForensicsAnalyzer:
    """
    Network Traffic Analysis for cybersecurity incident response
    """
    
    def __init__(self):
        self.traffic_data = self.create_realistic_scenario()
        self.flags_found = []
        self.iocs = {
            'malicious_ips': [],
            'malicious_domains': [],
            'file_hashes': [],
            'suspicious_ports': []
        }
    
    def create_realistic_scenario(self):
        """Create a realistic corporate network compromise scenario"""
        return {
            "incident_id": "INC-2025-0912",
            "scenario": "Employee workstation compromise via phishing email leading to data exfiltration",
            "network_info": {
                "internal_subnet": "192.168.1.0/24",
                "compromised_host": "192.168.1.105",
                "domain_controller": "192.168.1.10",
                "dns_server": "192.168.1.1",
                "gateway": "192.168.1.1"
            },
            "timeline": [
                {
                    "timestamp": "2025-09-12 09:15:23.456",
                    "src_ip": "smtp.company.com",
                    "dst_ip": "192.168.1.105",
                    "protocol": "SMTP",
                    "port": 25,
                    "description": "Phishing email delivered",
                    "payload": "Subject: URGENT: Account Security Update Required",
                    "details": "Email contains malicious attachment: invoice.pdf.exe",
                    "malicious": True,
                    "severity": "high"
                },
                {
                    "timestamp": "2025-09-12 09:18:47.123",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "malicious-update.evil-corp.com",
                    "protocol": "HTTP",
                    "port": 80,
                    "description": "User clicked phishing link",
                    "payload": "GET /secure-update.php?user=victim&token=abc123 HTTP/1.1",
                    "details": "Initial compromise vector - credential harvesting",
                    "malicious": True,
                    "severity": "critical"
                },
                {
                    "timestamp": "2025-09-12 09:19:15.789",
                    "src_ip": "malicious-update.evil-corp.com",
                    "dst_ip": "192.168.1.105",
                    "protocol": "HTTP",
                    "port": 80,
                    "description": "Malware payload delivery",
                    "payload": "HTTP/1.1 200 OK\nContent-Type: application/octet-stream\nContent-Length: 2457600",
                    "details": "2.4MB malware binary downloaded",
                    "malicious": True,
                    "severity": "critical",
                    "file_hash": "5d41402abc4b2a76b9719d911017c592"
                },
                {
                    "timestamp": "2025-09-12 09:22:33.012",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "185.159.157.13",
                    "protocol": "TCP",
                    "port": 4444,
                    "description": "Reverse shell connection established",
                    "payload": "SYN -> 185.159.157.13:4444",
                    "details": "Persistent backdoor connection to C2 server",
                    "malicious": True,
                    "severity": "critical"
                },
                {
                    "timestamp": "2025-09-12 09:25:10.345",
                    "src_ip": "185.159.157.13",
                    "dst_ip": "192.168.1.105",
                    "protocol": "TCP",
                    "port": 4444,
                    "description": "Remote command execution",
                    "payload": base64.b64encode(b'whoami && hostname && ipconfig').decode(),
                    "details": "System reconnaissance commands",
                    "malicious": True,
                    "severity": "high"
                },
                {
                    "timestamp": "2025-09-12 09:28:45.678",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "192.168.1.10",
                    "protocol": "SMB",
                    "port": 445,
                    "description": "Lateral movement attempt",
                    "payload": "\\\\DC01\\ADMIN$",
                    "details": "Attempting to access domain controller shares",
                    "malicious": True,
                    "severity": "high"
                },
                {
                    "timestamp": "2025-09-12 09:35:12.234",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "185.159.157.13",
                    "protocol": "HTTPS",
                    "port": 443,
                    "description": "Encrypted data exfiltration",
                    "payload": "POST /upload.php HTTP/1.1\nContent-Length: 15728640",
                    "details": "15.7MB of encrypted data uploaded",
                    "malicious": True,
                    "severity": "critical"
                },
                {
                    "timestamp": "2025-09-12 09:40:33.567",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "paste-service.com",
                    "protocol": "HTTPS",
                    "port": 443,
                    "description": "Credential dump to pastebin",
                    "payload": "POST /api/paste HTTP/1.1",
                    "details": "Stolen credentials uploaded to public paste service",
                    "malicious": True,
                    "severity": "critical"
                }
            ],
            "dns_queries": [
                {
                    "timestamp": "2025-09-12 09:18:40.100",
                    "query": "malicious-update.evil-corp.com",
                    "response": "203.0.113.42",
                    "query_type": "A",
                    "suspicious": True
                },
                {
                    "timestamp": "2025-09-12 09:22:25.200",
                    "query": "dGVzdGRhdGE=.tunnel.evil-corp.com",
                    "response": "TXT: v=received",
                    "query_type": "TXT", 
                    "suspicious": True,
                    "notes": "DNS tunneling detected - Base64 encoded data"
                },
                {
                    "timestamp": "2025-09-12 09:30:15.300",
                    "query": "Y29tbWFuZA==.tunnel.evil-corp.com",
                    "response": "TXT: v=ack",
                    "query_type": "TXT",
                    "suspicious": True,
                    "notes": "DNS tunneling - command channel"
                }
            ]
        }
    
    def print_banner(self):
        """Print analysis banner"""
        print("🌐 NETWORK FORENSICS ANALYSIS - CTF Challenge 3")
        print("=" * 60)
        print(f"Incident ID: {self.traffic_data['incident_id']}")
        print(f"Scenario: {self.traffic_data['scenario']}")
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print()
    
    def analyze_timeline(self):
        """Analyze the complete attack timeline"""
        print("🕐 ATTACK TIMELINE ANALYSIS")
        print("-" * 40)
        
        malicious_events = [event for event in self.traffic_data["timeline"] if event.get("malicious", False)]
        
        print(f"📊 Total network events: {len(self.traffic_data['timeline'])}")
        print(f"🚨 Malicious events identified: {len(malicious_events)}")
        print()
        
        print("📋 CHRONOLOGICAL ATTACK PROGRESSION:")
        for i, event in enumerate(malicious_events, 1):
            print(f"\n{i}. [{event['timestamp']}]")
            print(f"   🔗 Connection: {event['src_ip']}:{event.get('port', 'N/A')} -> {event['dst_ip']} ({event['protocol']})")
            print(f"   📝 Event: {event['description']}")
            print(f"   ⚠️  Severity: {event['severity'].upper()}")
            print(f"   📄 Details: {event['details']}")
            
            # Extract IOCs
            if event['dst_ip'] not in ['192.168.1.105', '192.168.1.10', '192.168.1.1']:
                if '.' in event['dst_ip'] and not event['dst_ip'].startswith('192.168.'):
                    self.iocs['malicious_ips'].append(event['dst_ip'])
            
            if 'evil-corp.com' in event.get('dst_ip', '') or 'evil-corp.com' in event.get('payload', ''):
                domain = event['dst_ip'] if 'evil-corp.com' in event['dst_ip'] else 'evil-corp.com'
                self.iocs['malicious_domains'].append(domain)
            
            if event.get('file_hash'):
                self.iocs['file_hashes'].append(event['file_hash'])
                
            if event.get('port') in [4444, 8080, 31337]:
                self.iocs['suspicious_ports'].append(event['port'])
        
        # Timeline analysis flag
        timeline_flag = "CTF{attack_timeline_successfully_reconstructed}"
        print(f"\n🚩 FLAG DISCOVERED: {timeline_flag}")
        self.flags_found.append(timeline_flag)
    
    def analyze_command_and_control(self):
        """Analyze C2 communications"""
        print("\n🎯 COMMAND & CONTROL ANALYSIS")
        print("-" * 35)
        
        c2_events = [event for event in self.traffic_data["timeline"] 
                    if event.get('port') == 4444 or 'command' in event.get('description', '').lower()]
        
        print("🔍 C2 Communication Pattern Analysis:")
        for event in c2_events:
            print(f"\n📡 C2 Traffic Detected:")
            print(f"   Time: {event['timestamp']}")
            print(f"   Direction: {event['src_ip']} -> {event['dst_ip']}")
            print(f"   Protocol/Port: {event['protocol']}:{event['port']}")
            
            # Decode Base64 commands if present
            if 'payload' in event and len(event['payload']) > 20:
                try:
                    decoded = base64.b64decode(event['payload']).decode('utf-8', errors='ignore')
                    if decoded.isprintable() and len(decoded) > 5:
                        print(f"   🔓 Decoded Command: {decoded}")
                except:
                    print(f"   📦 Payload: {event['payload'][:50]}...")
        
        # C2 analysis flag
        c2_flag = "CTF{command_and_control_analysis_complete}"
        print(f"\n🚩 FLAG DISCOVERED: {c2_flag}")
        self.flags_found.append(c2_flag)
    
    def analyze_dns_traffic(self):
        """Analyze DNS queries for tunneling and suspicious domains"""
        print("\n🌐 DNS TRAFFIC ANALYSIS")
        print("-" * 30)
        
        print("📋 DNS Query Analysis:")
        for query in self.traffic_data["dns_queries"]:
            print(f"\n🔍 DNS Query: {query['query']}")
            print(f"   Type: {query['query_type']}")
            print(f"   Response: {query['response']}")
            print(f"   Suspicious: {'🚨 YES' if query['suspicious'] else '✅ NO'}")
            
            if query.get('notes'):
                print(f"   Notes: {query['notes']}")
            
            # Check for DNS tunneling (Base64 in DNS)
            if '=' in query['query']:
                try:
                    subdomain = query['query'].split('.')[0]
                    decoded = base64.b64decode(subdomain + '==').decode('utf-8', errors='ignore')
                    if decoded.isprintable():
                        print(f"   🔓 Decoded Data: {decoded}")
                except:
                    pass
        
        # DNS analysis flag
        dns_flag = "CTF{dns_tunneling_and_exfiltration_detected}"
        print(f"\n🚩 FLAG DISCOVERED: {dns_flag}")
        self.flags_found.append(dns_flag)
    
    def analyze_data_exfiltration(self):
        """Analyze data exfiltration activities"""
        print("\n📤 DATA EXFILTRATION ANALYSIS")
        print("-" * 35)
        
        exfil_events = [event for event in self.traffic_data["timeline"] 
                       if 'exfiltration' in event.get('description', '').lower() or 
                          'upload' in event.get('payload', '').lower()]
        
        total_data_size = 0
        print("📊 Data Transfer Analysis:")
        
        for event in exfil_events:
            print(f"\n🚨 Data Exfiltration Event:")
            print(f"   Timestamp: {event['timestamp']}")
            print(f"   Destination: {event['dst_ip']}:{event['port']}")
            print(f"   Protocol: {event['protocol']}")
            
            # Extract data size from payload
            if 'Content-Length:' in event.get('payload', ''):
                size_match = re.search(r'Content-Length:\s*(\d+)', event['payload'])
                if size_match:
                    size_bytes = int(size_match.group(1))
                    size_mb = size_bytes / (1024 * 1024)
                    total_data_size += size_mb
                    print(f"   📊 Data Size: {size_mb:.1f} MB ({size_bytes:,} bytes)")
            
            print(f"   📝 Method: {event['description']}")
        
        print(f"\n📈 Total Data Exfiltrated: {total_data_size:.1f} MB")
        
        # Data exfiltration flag
        exfil_flag = "CTF{data_exfiltration_15MB_detected_and_quantified}"
        print(f"\n🚩 FLAG DISCOVERED: {exfil_flag}")
        self.flags_found.append(exfil_flag)
    
    def generate_iocs(self):
        """Generate Indicators of Compromise"""
        print("\n🚨 INDICATORS OF COMPROMISE (IOCs)")
        print("-" * 45)
        
        # Clean up and deduplicate IOCs
        self.iocs['malicious_ips'] = list(set(self.iocs['malicious_ips']))
        self.iocs['malicious_domains'] = list(set(self.iocs['malicious_domains']))
        self.iocs['file_hashes'] = list(set(self.iocs['file_hashes']))
        self.iocs['suspicious_ports'] = list(set(self.iocs['suspicious_ports']))
        
        print("📋 Network IOCs:")
        print(f"   🌐 Malicious IP Addresses: {len(self.iocs['malicious_ips'])}")
        for ip in self.iocs['malicious_ips']:
            print(f"     • {ip}")
        
        print(f"\n   🏷️  Malicious Domains: {len(self.iocs['malicious_domains'])}")
        for domain in self.iocs['malicious_domains']:
            print(f"     • {domain}")
        
        print(f"\n   🔌 Suspicious Ports: {len(self.iocs['suspicious_ports'])}")
        for port in self.iocs['suspicious_ports']:
            print(f"     • {port}/tcp")
        
        print(f"\n   #️⃣ File Hashes (MD5): {len(self.iocs['file_hashes'])}")
        for hash_val in self.iocs['file_hashes']:
            print(f"     • {hash_val}")
        
        # IOC generation flag
        ioc_flag = "CTF{comprehensive_ioc_extraction_completed}"
        print(f"\n🚩 FLAG DISCOVERED: {ioc_flag}")
        self.flags_found.append(ioc_flag)
        
        return self.iocs
    
    def generate_executive_summary(self):
        """Generate executive summary for management"""
        print("\n📊 EXECUTIVE SUMMARY")
        print("-" * 25)
        
        print("🎯 INCIDENT OVERVIEW:")
        print(f"   • Incident Type: Advanced Persistent Threat (APT)")
        print(f"   • Attack Vector: Spear-phishing email")
        print(f"   • Compromise Duration: ~25 minutes")
        print(f"   • Data Loss: 15.7 MB confirmed exfiltration")
        print(f"   • Affected Systems: 1 workstation, attempted lateral movement")
        
        print("\n⚡ KEY FINDINGS:")
        print(f"   • Total malicious events: {len([e for e in self.traffic_data['timeline'] if e.get('malicious')])}")
        print(f"   • C2 communications established")
        print(f"   • DNS tunneling for covert communications")
        print(f"   • Successful data exfiltration")
        print(f"   • Attempted lateral movement to domain controller")
        
        print("\n🛡️ IMMEDIATE ACTIONS REQUIRED:")
        print("   • Isolate affected workstation (192.168.1.105)")
        print("   • Block identified malicious IPs and domains")
        print("   • Reset credentials for potentially compromised accounts")
        print("   • Scan network for additional compromise indicators")
        print("   • Review email security controls")
        
        # Executive summary flag
        exec_flag = "CTF{executive_summary_and_recommendations_generated}"
        print(f"\n🚩 FLAG DISCOVERED: {exec_flag}")
        self.flags_found.append(exec_flag)
    
    def run_full_analysis(self):
        """Execute complete network forensics analysis"""
        self.print_banner()
        
        print("🔍 Starting comprehensive network traffic analysis...")
        print("Analysis includes: Timeline reconstruction, C2 analysis, DNS investigation, data exfiltration assessment\n")
        
        # Execute all analysis modules
        self.analyze_timeline()
        self.analyze_command_and_control()  
        self.analyze_dns_traffic()
        self.analyze_data_exfiltration()
        iocs = self.generate_iocs()
        self.generate_executive_summary()
        
        # Final summary
        print("\n" + "=" * 60)
        print("✅ NETWORK FORENSICS ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"🎉 Total Flags Discovered: {len(self.flags_found)}")
        print("\n📋 All Flags Found:")
        for i, flag in enumerate(self.flags_found, 1):
            print(f"   {i}. {flag}")
        
        # Master forensics flag
        master_flag = "CTF{network_forensics_incident_response_master_2025}"
        print(f"\n🏆 MASTER FLAG: {master_flag}")
        
        print(f"\n📊 Analysis Statistics:")
        print(f"   • Events Analyzed: {len(self.traffic_data['timeline'])}")
        print(f"   • IOCs Generated: {sum(len(v) for v in iocs.values())}")
        print(f"   • Attack Duration: 25 minutes")
        print(f"   • Severity Assessment: CRITICAL")
        
        return {
            'flags': self.flags_found + [master_flag],
            'iocs': iocs,
            'summary': 'Advanced network compromise with data exfiltration'
        }

if __name__ == "__main__":
    analyzer = NetworkForensicsAnalyzer()
    results = analyzer.run_full_analysis()
