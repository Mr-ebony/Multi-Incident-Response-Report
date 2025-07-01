# 🛡️ Incident Response Report

### 🎯 Incident Title: 
Brute-Force Login Attack on Windows

### 📅 Date & Time Detected:
- **Date & Time**: June 20, 2025 – 15:42 UTC

### 📍 Location / System Affected: 
Windows 10 VM - IP 192.168.1.101

### 👨‍💻 Analyst: Samson Ogunfuyi

---

# 🔎 1. Executive Summary

Brief overview of what happened:
- What type of incident occurred?
- How was it detected?
- What systems were affected?
- Summary of impact.

---

# 📚 2. Attack Description 
Provide a detailed narrative of the attack:
- What was the attack vector?
- What tools or commands were used by the attacker?
- Include technical details.

---

# 🧠  3. MITRE ATT&CK Mapping (If Applicable)

- **Tactic**: Credential Access
- **Technique**: Brute Force – [T1110](https://attack.mitre.org/techniques/T1110/)

| Tactic        | Technique          | ID        | Description                      |
|---------------|--------------------|-----------|----------------------------------|
| Credential Access | Brute Force        | T1110     | Repeated password attempts       |

---

# 🧾 4. Indicators of Compromise (IoCs)

Summarise key indicators found. Full CSV attached.

| Indicator Type | Value              | Source                   |
|----------------|--------------------|--------------------------|
| IP Address     | 192.168.1.200      | Splunk Log               |
| File Hash      | [EICAR hash]       | Windows Defender Alert   |
| Command        | powershell.exe ... | Event Viewer (4104)      |
| User Account   | attacker_user      | Windows Logon Event      |

---

---
# 📋  5. Detection and Logging

- Detection Tool: [e.g., Splunk, Windows Defender, Event Viewer]
- Relevant Event IDs: [e.g., 4625, 4688, 1116, 4104]
- Screenshots: [Insert or reference files]

---
# 🛠️  6. Containment & Remediation

- Blocked attacker IP via Windows firewall
- Alerted administrator
- Disabled affected user account for review

---
# 📈  7. Lessons Learned & Recommendations

- Need to implement account lockout policy
- Deploy better alerting for brute-force behavior
- Regular audit of EventCode 4625 trends

---
# 📎  8. Attachments

✅ IOC CSV File: `iocs_[attack].csv`  
✅ Screenshots: `screenshots/[relevant].png`  
✅ Splunk Dashboard Export: `splunk_dashboards/[attack]_dashboard.xml`  

---

