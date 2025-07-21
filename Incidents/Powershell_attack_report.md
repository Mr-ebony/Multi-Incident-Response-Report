# 🛡️ Incident Response Report

### 🎯 Incident Title: 
Suspicious PowerShell Execution

#### Incident Summary
| Field             | Details           | 
|--------------------|---------------------|
| Incident ID  | Malware Execution Simulation - EICAR Detection         |
| Date/Time Detected    | 2025-07-14, 09:32 UTC      |
|  Detected By   | Windows Defender Antivirus      |
| Severity Level | Severe         |
| Category   | Execution → PowerShell Abuse      |
| Status    | Investigated & Contained      |

### 🎈 Description of Incident
At approximately 09:32 UTC, the endpoint security system detected the execution of a suspicious PowerShell script on host WIN-ENG-PC01 under user eng-lab\tempuser.
The command displayed signs of obfuscation and encoded payloads, indicating possible malware staging or command-and-control activity. The event was captured by PowerShell Script Block Logging (Event ID 4104) and later blocked by policy (Event ID 4105).
No malware was successfully downloaded or executed, and the script was blocked before it could have any impact.

### 🎈 Indicators of Compromise (IOCs)
| IOC Type             | Value           | 
|--------------------|---------------------|
| TImestamp  | 2025-07-14 09:32:41 UTC         |
| User    | `eng-lab\tempuser`      |
|  Host   | `WIN-ENG-PC01`      |
| Event ID | 4104, 4105         |
| Command Observed   | `powershell -w hidden -nop -enc SQBFAFgAKABQ...      |
| Decoded Payload    | Included use `IEX`, `Net.WebClient`, and suspicious URL download      |
| File Path (if any) | N/A (memory-only execution attemted         |
| Process Parent   | `explorer.exe` → `powershell.exe`      |
| Action Taken    | Script blocked: user isolated: logs archived      |

### 🎈 Root Cause Analysis
The script was likely triggered via a malicious shortcut (.lnk file) or embedded within a phishing payload. Initial analysis suggests command and control (C2) staging behavior, though no outbound traffic was recorded.

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
+ Machine was **isolated from the network**

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
