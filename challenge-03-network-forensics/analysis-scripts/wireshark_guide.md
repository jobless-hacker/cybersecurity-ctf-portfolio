# Wireshark Analysis Guide - Challenge 3

## Quick Analysis Commands

### 1. Initial Triage
```
# Get basic statistics (if you had a real PCAP file)
capinfos malicious_traffic.pcap

# Quick protocol overview
tshark -r malicious_traffic.pcap -q -z conv,ip
tshark -r malicious_traffic.pcap -q -z prot
```

### 2. Suspicious Traffic Filters

#### Find HTTP POST requests (potential data exfiltration)
```
http.request.method == "POST"
```

#### Find Base64 encoded data in HTTP
```
http contains "base64" or http.request.uri contains "="
```

#### Find connections to suspicious ports
```
tcp.port == 4444 or tcp.port == 8080 or tcp.port == 31337
```

#### Find long connections (potential C2)
```
tcp.stream eq 0 and tcp.len > 0
```

### 3. DNS Analysis
```
# DNS queries to suspicious domains
dns.qry.name contains "evil" or dns.qry.name contains "malicious"

# DNS tunneling detection
dns.qry.name contains "=" or dns.txt contains "="

# Unusual DNS record types
dns.qry.type != 1 and dns.qry.type != 28
```

### 4. File Transfer Detection
```
# HTTP file downloads
http.response.code == 200 and http.content_length > 1000000

# FTP transfers
ftp-data

# Large data transfers
frame.len > 1500 and tcp.len > 1400
```

## Step-by-Step Analysis Process

### Phase 1: Network Overview
1. Load PCAP in Wireshark
2. Check Statistics -> Protocol Hierarchy
3. Check Statistics -> Conversations
4. Look for unusual protocols or large data transfers

### Phase 2: Timeline Analysis
1. Sort by time
2. Look for sequences of related traffic
3. Identify initial compromise vector
4. Track lateral movement

### Phase 3: Content Analysis
1. Follow TCP streams for detailed analysis
2. Export objects from HTTP traffic
3. Decode Base64 content
4. Extract files for malware analysis

### Phase 4: IOC Extraction
1. Document suspicious IPs
2. Extract domain names
3. Note file hashes
4. Record timestamps for timeline

## Expected Findings

### Compromise Vector
- Phishing email with malicious link
- Initial HTTP GET to malicious domain
- Malware payload download

### Command & Control
- Reverse shell on port 4444
- Base64 encoded commands
- Persistent connection to attacker IP

### Data Exfiltration
- Large HTTPS uploads
- Database dumps via FTP
- Credential theft to pastebin

### Lateral Movement
- SMB connections to other hosts
- Administrative tool usage
- Domain controller access attempts

## Analysis Techniques

### 1. Protocol Analysis
```
# Identify unusual protocols or ports
tshark -r traffic.pcap -q -z prot

# Look for non-standard port usage  
tshark -r traffic.pcap -Y "tcp.port == 4444"
```

### 2. DNS Analysis
```
# Find DNS tunneling
tshark -r traffic.pcap -Y 'dns.qry.name contains "="'

# Suspicious domains
tshark -r traffic.pcap -Y 'dns.qry.name contains "evil"'
```

### 3. HTTP Analysis  
```
# Large downloads (malware)
tshark -r traffic.pcap -Y "http.response.code == 200 and http.content_length > 1000000"

# Data uploads (exfiltration)
tshark -r traffic.pcap -Y "http.request.method == POST and http.content_length > 1000000"
```

### 4. Content Extraction
```
# Export HTTP objects
tshark -r traffic.pcap --export-objects http,extracted_files/

# Decode Base64 in traffic
tshark -r traffic.pcap -Y "tcp.payload contains 'base64'"
```

## Professional Analysis Workflow

### 1. Preparation
- Set up isolated analysis environment
- Document chain of custody
- Create analysis timeline template

### 2. Initial Assessment
- File integrity verification
- Basic statistics gathering
- Protocol hierarchy review

### 3. Deep Analysis
- Timeline reconstruction
- IOC extraction
- Behavioral analysis

### 4. Reporting
- Executive summary creation
- Technical details documentation
- Remediation recommendations

This guide provides the foundation for professional network forensics analysis capabilities.
```

