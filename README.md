# Multi-Incident-Response-Report

## Brute-Force Attack Incident Response Report
This project simulates a real-world incident response using a brute-force login attack. I investigated the incident using Splunk logs, documented key Indicators of Compromise (IoCs), and mapped the behaviour to MITRE ATT&CK.
See `Brute_Force_incident_report.md` for the full report. Additionally, to see how a  Brute-force attack was done, please visit my [Splunk-threat-hunting-lab](https://github.com/Mr-ebony/Splunk-threat-hunting-lab.git) project.

## Malware Execution Using EICAR (Safe Simulation)

### Steps
+ **Open Browser on the Windows VM**
+ Visit the official EICAR test file site
  🔗 [https://www.eicar.org/download-anti-malware-tesfile/](https://www.eicar.org/download-anti-malware-tesfile/)
+ Download the `eicar.com` file - your antivirus or Windows Defender will likely alert or block it.
  #### Alternative way to download if it is blocked (Manual Method)
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
+ Attempt to run it on your desktop (it will likely get a block event).
+ Open **Windows Event Viewer → Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational**, look for logs from `Window Defender`
### Common IOCs that can be extracted from Windows Defender Malware Logs
|______________ |
     
  
