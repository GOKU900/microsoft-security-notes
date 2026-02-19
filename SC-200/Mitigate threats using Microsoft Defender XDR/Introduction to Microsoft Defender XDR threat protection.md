# Microsoft Defender XDR - Study Notes
**Module 1 of SC-200 Learning Path**

## What is Microsoft Defender XDR? 

Microsoft Defender XDR is an enterprise defense suite that uses signals from endpoints, email, identity, applications, and the cloud to detect and mitigate threats. The data from these multiple signals is correlated by the platform
to create incidents from related alerts. These incidents show an entire attack chain rather than individial separated alerts per signal. This reduces the investigation time for analysts and other security proffesionals.

## Products That Feed Into Defender XDR

| Product | What It Protects | Key Signal
|---|---|---|
| Defender for Endpoint (MDE) | Devices / endpoints | Process creation, file events, network connections |
| Defender for Identity (MDI) | Active Directory / identities | Lateral movement, credential theft, recon activity |
| Defender for Office 365 (MDO) | Email and collaboration (Exchange Online, Microsoft Teams, Sharepoint Online, OneDrive for Business, office apps e.g. WORD, EXCEL, POWERPOINT) | Phishing, malicious attachments, BEC |
| Defender for Cloud Apps (MDCA) | SaaS applications which also include Exchange, OneDrive, SharePoint, and Teams | Impossible travel, mass downloads, OAuth abuse |
| Microsoft Entra ID Protection | Cloud identities | Risky sign-ins, leaked credentials |
| Defender for Iot (& OT) | IoT Devices | IoT Device Exploitation | 

## What is Microsoft Security Graph?
The Microsoft Security Graph is a RESTful API that we can use to access data from multiple Microsoft  services. For example, we can get data from all across the enterpise environment for Booking, Calendar, Excel, Purview EDiscovery, OneDrive,
OneNote, Outlook/Exchange, SharePoint, Teams and so many other services and products. For our security context, we can get data from Entra ID, Advanced Threat Analytics, Identity Manager, Intune, devices ect... This allows us to pull data from many places in order
to generate alerts, incidents and perform investigations.

> **Practical note:** I haven't had the opportunity to work with the the Microft Graph API in my current role. It seems to me the API is typically used by develeopers or by engineers. However,based on what I am reading it could come very useful to pull information that is not easily available in the XDR or Sentinel GUI. GRAPH EXPLORER is a tool to start exploring Graph APIs.

## Resources Used for This Module
- [Microsoft Learn SC-200 Path — Module 1] (https://learn.microsoft.com/en-us/training/modules/introduction-microsoft-365-threat-protection/)
- [Microsoft Defender XDR Documentation] (https://learn.microsoft.com/en-us/microsoft-365/security/defender/)

*Notes are written in my own words for retention. Some definitions paraphrased from Microsoft Learn.*
