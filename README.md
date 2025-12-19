# SPLUNK-101-Capstone-Project
Suspicious Mouse Movement Investigation

# Objective
This investigation demonstrates the application of Splunk SIEM capabilities to detect, analyze, and respond to a real-world security incident involving unauthorized remote access and malware deployment. The primary focus was to correlate multiple data sources including authentication logs, process execution events, and scheduled task creation to reconstruct the attack timeline and identify indicators of compromise (IOCs). This hands-on investigation enhanced understanding of attack patterns, lateral movement techniques, and persistence mechanisms commonly employed by threat actors.

# Skills Learned
Advanced log correlation and timeline reconstruction using Splunk Search Processing Language (SPL)
Proficiency in identifying and analyzing brute force authentication attacks through failed logon pattern recognition
Ability to detect malicious PowerShell execution and command-line obfuscation techniques
Enhanced understanding of Windows Task Scheduler abuse for persistence mechanisms
Development of incident response methodology including IOC identification and containment recommendations
Critical thinking in differentiating legitimate user activity from malicious actor behavior
Knowledge of Remote Desktop Protocol (RDP) security vulnerabilities and exploitation techniques

# Tools Used
Splunk Enterprise SIEM for log ingestion, correlation, and timeline analysis
Windows Security Event Logs (Event IDs 4624, 4625) for authentication monitoring
Sysmon logs for process execution and command-line parameter analysis
Windows Task Scheduler logs for scheduled task creation detection
Network traffic analysis for identifying suspicious RDP connections from IP 172.16.0.184

# Investigation Summary
Findings
- Time of Report: 2025-10-15 13:00:00 UTC
- Affected Host: FRONTDESK-PC1
- Compromised User: Ryan.Adams
- IOC IP Address: 172.16.0.184
- Malicious File: python.exe (located in C:\Users\Ryan.Adams\Music)
- Persistence Mechanism: Scheduled Task "PythonUpdate"

Attack Timeline
- 2025-10-15 12:00:00 UTC to 12:52:11 UTC – Multiple failed logon attempts detected (Brute force attack pattern)
- 2025-10-15 12:52:12 UTC – Successful authentication from IP 172.16.0.184 to Ryan.Adams account
- 2025-10-15 13:02:14 UTC – Task Scheduler service accessed
- 2025-10-15 13:03:57 UTC – PowerShell execution launched by attacker
- 2025-10-15 13:04:08 UTC – Attacker navigated to "C:\Users\Ryan.Adams\Music" directory
- 2025-10-15 13:04:53 UTC – Malicious PowerShell command executed: PowerShell.exe -noexit -command Set-Location -literalPath 'C:\Users\Ryan.Adams\Music'
- 2025-10-15 13:04:59 UTC - Malicious scheduled task created for persistence: C:\Windows\system32\schtasks.exe /create /tn PythonUpdate /tr C:\Users\Ryan.Adams\Music\python.exe /sc onstart /ru SYSTEM /f

# Investigation Analysis
On October 15, 2025, at approximately 13:00 UTC, Ryan Adams reported suspicious mouse movement on his workstation (FRONTDESK-PC1). Subsequent forensic analysis confirmed a security breach involving unauthorized remote access, malware deployment, and establishment of persistence mechanisms.
- Who? User account Ryan.Adams on workstation FRONTDESK-PC1
- What Happened? An external threat actor successfully compromised the workstation through brute force authentication, gained remote access via RDP, downloaded and executed a malicious payload (python.exe), and created a scheduled task to maintain persistent access with SYSTEM-level privileges.
- When? Attack began at 12:00 UTC with brute force attempts, successful compromise at 12:52 UTC, malware deployment at 13:04 UTC. User reported suspicious activity at 13:00 UTC, only 9 minutes after malicious activity commenced.
- Where? Workstation FRONTDESK-PC1 belonging to Ryan Adams
- Why? Likely motives include establishing persistent access for data exfiltration, credential harvesting, lateral movement preparation, or deployment of additional payloads.
- How? Attack vector involved RDP brute force authentication from IP 172.16.0.184, followed by remote access to deploy malware and create scheduled tasks for persistence. The use of PowerShell and legitimate system tools (schtasks.exe) demonstrates living-off-the-land (LOtL) techniques to evade detection.

# Immediate Recommendations
- Containment: Immediately isolate FRONTDESK-PC1 from the network to prevent lateral movement and data exfiltration
- Credential Reset: Force password reset for Ryan.Adams and any accounts with similar access privileges
- Forensic Preservation: Do not power down the system; create a forensic image for further analysis
- IOC Hunting: Search all systems for connections from IP 172.16.0.184, presence of python.exe in non-standard locations, and scheduled tasks named "PythonUpdate"
- Access Review: Audit RDP access logs across the environment for additional compromise indicators
- Malware Analysis: Submit python.exe to sandbox environment for behavioral analysis and signature generation
- Incident Response: Activate incident response procedures and notify appropriate stakeholders per organizational policy
