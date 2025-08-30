# 🛡️ Incident Response Report

### 🎯 Incident Title: 
Privilege Escalation Simulation

### 1. ℹ Incident Metadata
- **Incident ID:** IR-2025-002  
- **Date & Time Detected:** August 26, 2025, 15:12 UTC  
- **Reported By:** Window Event Viewer – “Suspicious Privilege Escalation”  
- **Severity:** High  
- **Status:** Closed (Simulated Lab Exercise)

---

### 2. 🔎 Executive Summary
This incident report documents a simulated **Privilege Escalation attack** performed in a controlled home lab environment.  
The attacker, using a compromised low-privilege account (`samson1`), attempted to escalate privileges to gain administrative control.  
Logs were collected from **Windows Event Viewer** and ingested into **Splunk** for analysis.  

The purpose of this simulation was to test detection capabilities, analyse relevant security logs, and demonstrate the incident response process.

---

### 3. 🏹 Attack Description
- **Initial Access:** Low-privilege user account `samson1` was already present on the system.  
- **Action Taken:** Attacker attempted to privilede escalation using:
  1. Simulate UAC Bypass
  2. Use WinPEAS (Automated Escalation Scanner)
 **Goal:** Obtain elevated permissions and access to restricted system resources.

---

### 4. 🧠 MITRE ATT&CK Mapping


| Tactic | Techniques ID              | Techniques Name                   |
|----------------|--------------------|--------------------------|
| Privilege Escalation     | T1078      | Valid Accounts              |
| Privilege Escalation      | T1136.001      | Create Account: Local   |
| Privilege Escalation       | T1098 | Account Manipulation     |
| Defense Evasion   | T1070.004     | File Deletion (account cleanup)     |

---

### 5. 📜 Indicators of Compromise (IOCs)

| IOC Type | Value             |
|----------------|--------------------|
| Event ID     | 4728 (User added to group)      |
| Event ID      | 4726 (User account deleted)   |
| Event ID       | 4624 (Successful logon of `samson1`) |
| Event ID   | 4672 (Special privileges assigned)   |
| Usernames      | `samson1` (test accounts) |
| Command Executed   | `net localgroup Administrators analyst1 /add`     |

---

### 6. 📜 Detection & Logging Details

- **Event Viewer Logs:**

  - Security → Event ID 4728 confirmed analyst1 was added to the Administrators group.

  - Event ID 4624 confirmed successful logon with analyst1.

  - Event ID 4672 confirmed assignment of admin privileges.
- **Splunk Queries:**

```cmd
index=wineventlog EventCode=4728

```
