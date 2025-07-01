# 🛡️ Incident Response Report

### 🎯 Incident Title: 
Brute-Force Login Attack on Windows

### 📅 Date & Time Detected:
- June 27, 2025 – 17:40:14
- June 27, 2025 – 17:40:13
- June 27, 2025 – 17:40:11
- June 27, 2025 – 15:19:57
- June 27, 2025 – 14:44:20
- June 27, 2025 – 14:26:02

### 📍 Location / System Affected: 
Windows 10 VM - IP 192.168.100.3

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

| Indicator Type | Value              | Description                   |
|----------------|--------------------|--------------------------|
| Src IP Address     | 192.168.100.2      | Kali Linux VM (Attacker)              |
| Target IP Address      | 192.168.100.3      | Windows VM (Attacked)   |
| EventCode        | 4625 | Failed Log on     |
| Port   | 3389      | Remote Desktop Protocol      |
| Username  | Samson      | Account used during attack      |



---

---
# 📋  5. Detection and Logging

- Detection Tool: [e.g., Splunk, Windows Defender, Event Viewer]
- Relevant Event IDs: [e.g., 4625]
- [Screenshots](https://github.com/Mr-ebony/Splunk-threat-hunting-lab.git)

---
# 🛠️  6. Containment & Remediation

- Blocked attacker IP via Windows firewall
- Alerted administrator
- Disabled the affected user account for review

---
# 📈  7. Lessons Learned & Recommendations

- Need to implement account lockout policy
- Deploy better alerting for brute-force behaviour
- Regular audit of EventCode 4625 trends

---
# 📎  8. Attachments

✅ IOC CSV File: `Indicators/iocs_brute_force.csv`  
✅ Screenshots: [Splunk-threat-hunting-lab/screenshots](https://github.com/Mr-ebony/Splunk-threat-hunting-lab.git)

---

