# 🛡️ Incident Response Report

### 🎯 Incident Title: 
Suspicious PowerShell Execution

#### Incident Summary
| Field             | Details           | 
|--------------------|---------------------|
| User | DESKTOP-G6IINP6\Samson         |
| Date/Time Detected    | 2025-07-21, 22:42:53      |
|  Detected By   | Windows PowerShell Script Block Logging (Event ID 4104)      |
| Severity Level | Warning         |
| Category   | Execution → PowerShell Abuse      |
| Status    | Blocked      |

### 🎈 Description of Incident
At approximately 22:42 UTC, the endpoint security system detected the execution of a suspicious PowerShell script on host DESKTOP-G6IINP6 under user DESKTOP-G6IINP6\Samson.
The command displayed signs of obfuscation and encoded payloads, indicating possible malware staging or command-and-control activity. The event was captured by PowerShell Script Block Logging (Event ID 4104).

### 🎈 Indicators of Compromise (IOCs)
| IOC Type             | Value           | 
|--------------------|---------------------|
| TImestamp  | 2025-07-21, 22:42:53         |
| User    | `DESKTOP-G6IINP6\Samson`      |
|  Host   | `DESKTOP-G6IINP6`      |
| Event ID | 4104         |
| Command Name   | Invoke-WebRequest      |
| Action Taken    | Script blocked      |

### 🎈 Impact Assessment
| Area             | Status           | 
|--------------------|---------------------|
| System Integrity  | Unaffected         |
| Confidentiality    | No data exfiltration detected      |
|  Availability   | No service disruption      |
| Business Impact | Non         |

### 🎈 Response Actions Taken
+ PowerShell script was **blocked and logged** via Group Policy and Defender rules
+ User session was terminated

### 🎈 Lessons Learned
+ PowerShell is a powerful tool commonly abused in modern attacks
+ Script block logging (4104) was **critical in early detection**
+ Enhanced endpoint visibility (e.g. Sysmon) should be enabled where possible

### 🎈 Recommendations
| Area             | Action           | 
|--------------------|---------------------|
| Endpoint Config  | Enforce strict PowerShell logging (4104, 4105, 4688)         |
| User Awareness    | Reinforce phishing and script attack awareness      |
|  Defensive Tools   | Add known pattern (e.g. IEX + WebClient) to detection rules      |
| Network Monitoring | Monitor suspicious PowerShell-generated DNS or HTTP traffic         |
