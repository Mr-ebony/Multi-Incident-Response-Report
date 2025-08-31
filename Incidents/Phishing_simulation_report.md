# 🛡️ Incident Response Report

### 🎯 Incident Title: 
Phishing Simulation (Safe Attachment)

## 1. 📅 Incident Metadata
- **Incident ID:** IR-2025-003  
- **Date & Time Detected:** <YYYY-MM-DD HH:MM UTC>  
- **Reported By:** User action & Splunk monitoring  
- **Severity:** Medium  
- **Status:** Closed (Simulated Lab Exercise)

---

### 2. 📍 Executive Summary
This exercise simulated a **phishing email** delivering a **benign attachment** and a harmless link to a local web server.  
The goal was to validate visibility and detections for user-executed content from email, and to practice incident documentation and response.

---

### 3. 🧨 Attack Description
- **Vector:** Phishing email to a local test inbox (smtp4dev).  
- **Attachment:** `invoice.docx` (benign). Optionally `invoice.docm` (macro-enabled with **no code**) to show security warning.  
- **Lure:** “Urgent invoice due” + link to `http://<KALI_IP>:8000/pay`.  
- **User Action:** Opened the attachment and clicked the link.  
- **Outcome:** Office process executed; outbound HTTP request observed (local server hit).

---

### 4. 📑 MITRE ATT&CK Mapping

| Tactic         | Technique ID | Technique Name                 |
|----------------|--------------|--------------------------------|
| Initial Access | T1566        | Phishing                       |
| Initial Access | T1566.001    | Spearphishing Attachment       |
| Execution      | T1204        | User Execution                 |

---

### 5. 🚦 Indicator of Compromise (IOCs)

| IOC Type      | Value                                      | Source                          |
|---------------|--------------------------------------------|----------------------------------|
| Email Subject | Urgent: Invoice Overdue                    | smtp4dev message                |
| Sender        | it@lab.local                               | smtp4dev headers                |
| Attachment    | invoice.docx / invoice.docm                | smtp4dev message                |
| Process       | WINWORD.EXE / EXCEL.EXE                    | Win Security Log (4688)         |
| Browser Proc  | msedge.exe / chrome.exe                    | Win Security Log (4688)         |
| URL Clicked   | http://<KALI_IP>:8000/pay                  | Web server access log           |
| User          | <victim username>                          | Logon context / Event 4688      |

---
### 6. Detection & Logging Details

**Event Viewer (Windows):**
- `Security`  
  - **4688** – A new process has been created (Office / browser)  
- (Optional) `Security`  
  - **5156/5158** – Filtering Platform connections (if enabled)  

**Splunk Queries:**

```spl
source="WinEventLog:Security" EventCode=4688
| rex "New Process Name:\s+(?<new_process>.*)"
| rex "Creator Process Name:\s+(?<parent_process>.*)"
| rex "Command Line:\s+(?<cmdline>.*)"
| search new_process="*\\WINWORD.EXE" OR new_process="*\\EXCEL.EXE" OR new_process="*\\chrome.exe" OR new_process="*\\msedge.exe"
| table _time Account_Name new_process parent_process cmdline ComputerName

```
(Optional, if network audit is enabled)

```spl
source="WinEventLog:Security" (EventCode=5156 OR EventCode=5158)
| search DestAddress="<KALI_IP>"
| table _time SourceAddress DestAddress Application

```
---
### 7. 🛠 Containment & Remediation
- Verified the attachment was benign; no malicious behavior observed.
- Educated user on phishing indicators (urgent tone, invoice lure, unexpected attachments).
- Added Splunk alert for Office processes launched from Downloads/Temp paths.
- (Optional) Enabled Sysmon for enhanced process/network telemetry.

---
### 8. 📈 Lessons Learned & Recommendations
- User execution remains a key risk; detections must focus on process origins and common delivery paths.
- Alert when Office apps start from Downloads/Temp or spawn scripting tools (PowerShell, cmd).
- Consider attachment sandboxing or mark-of-the-web checks for internet-downloaded files.
- Add a phishing awareness playbook to the IR runbook.

---
### 9. 📎 Attachments
- Screenshots:
  - screenshots/phishing/smtp4dev_message.png
  - screenshots/phishing/word_open.png
  - screenshots/phishing/splunk_4688_office.png
  - screenshots/phishing/kali_http_access.png

- IOC CSV: indicators/iocs_phishing.csv
- (Optional) Splunk saved search/alert export
