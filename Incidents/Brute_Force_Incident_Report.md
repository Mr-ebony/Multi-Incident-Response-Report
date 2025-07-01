# 🛡️ Incident Response Report

## 📌 Incident Summary
- **Date & Time**: June 20, 2025 – 15:42 UTC
- **Incident Type**: Brute-force login attack
- **System Affected**: Windows VM (Victim Machine)
- **Detected By**: Splunk Alert

---

## 🧾 Indicators of Compromise (IoCs)
- Multiple failed SSH login attempts
- EventCode: 4625 in Windows logs
- Attempts from IP: 192.168.1.150 (Kali attacker)

---

## 🔍 Investigation Timeline

| Time | Event |
|------|-------|
| 15:42 | Multiple failed logins detected |
| 15:43 | Splunk triggered alert |
| 15:45 | Analyst reviewed Event Logs |
| 15:50 | Source IP identified: 192.168.1.150 |

---
## 🛠 Containment Actions
- Blocked attacker IP via Windows firewall
- Alerted administrator
- Disabled affected user account for review

---

## ✅ Lessons Learned
- Need to implement account lockout policy
- Deploy better alerting for brute-force behavior
- Regular audit of EventCode 4625 trends

## 🧠 MITRE ATT&CK Mapping
- **Tactic**: Credential Access
- **Technique**: Brute Force – [T1110](https://attack.mitre.org/techniques/T1110/)

---

