# Mitigate incidents using Microsoft Defender

## What is Microsoft Defender Portal?
Its a portal that has a unified view of incidents and actions taken. Think of it as a specialized workspace. The Defender portal is where the XDR lives and we can see the incidents being created.

[Defender Portal](https://security.microsoft.com/)

## Important things to know
- The Defender portal used role-based access control. This means that your role will determine what you can see and do in the portal.
- The portal includes access to:
  |Product | Description |
  |---|---|
  |Microsoft Defender for Office 365 | Microsoft Defender for Office 365 helps organizations secure their enterprise with a set of prevention, detection, investigation and hunting features to protect email, and Office 365 resources.
  |Microsoft Defender for Endpoint | Delivers preventative protection, post-breach detection, automated investigation, and response for devices in your organization.
  |Microsoft Defender XDR | is part of Microsoft’s Extended Detection and Response (XDR) solution that uses the Microsoft 365 security portfolio to automatically analyze threat data across domains, and build a picture of an attack on a single dashboard.
  |Microsoft Defender for Cloud Apps | Is a comprehensive cross-SaaS and PaaS solution bringing deep visibility, strong data controls, and enhanced threat protection to your cloud apps.
  |Microsoft Defender for Identity | Is a cloud-based security solution that uses your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.
  |Microsoft Defender Vulnerability Management | Delivers continuous asset visibility, intelligent risk-based assessments, and built-in remediation tools to help your security and IT teams prioritize and address critical vulnerabilities and misconfigurations across your organization.
  |Microsoft Defender for IoT | Operational Technology (OT) involves the specialized hardware and software used to monitor and control physical processes in critical sectors such as manufacturing, utilities, pharmaceuticals, and more. Microsoft Defender for IoT, available within the Microsoft Defender portal, is designed to secure OT environments.
  |Microsoft Sentinel | Integrate Microsoft Defender XDR with Microsoft Sentinel to stream all Defender XDR incidents and advanced hunting events into Microsoft Sentinel and keep the incidents and events synchronized between the Azure and Microsoft Defender portals.

## What is an Incident?
An incident is a collection of correlated alerts that make up the story of an attack. Within the story, we can see all the involved entities in the attack: users, devices, hashes, domains, applications ect...

## How is MITRE ATT&CK used within the portal?
The incident and alert categories align closely with the attack tactics and techniques in the MITRE ATT&CK Enterprise matrix.

| Category | Description |
|---|---|
|Collection | Locating and collecting data for exfiltration
|Command and control | Connecting to attacker-controlled network infrastructure to relay data or receive commands
|Credential access | Obtaining valid credentials to extend control over devices and other resources in the network
|Defense evasion | Avoiding security controls by, for example, turning off security apps, deleting implants, and running rootkits
|Discovery | Gathering information about important devices and resources, such as administrator computers, domain controllers, and file servers
|Execution | Launching attacker tools and malicious code, including RATs and backdoors
|Exfiltration | Extracting data from the network to an external, attacker-controlled location
|Exploit | Exploit code and possible exploitation activity
|Initial access | Gaining initial entry to the target network, usually involving password-guessing, exploits, or phishing emails
|Lateral movement | Moving between devices in the target network to reach critical resources or gain network persistence
|Malware | Backdoors, trojans, and other types of malicious code
|Persistence | Creating autostart extensibility points (ASEPs) to remain active and survive system restarts
|Privilege escalation | Obtaining higher permission levels for code by running it in the context of a privileged process or account
|Ransomware | Malware that encrypts files and extorts payment to restore access
|Suspicious activity | Atypical activity that could be malware activity or part of an attack
|Unwanted software | Low-reputation apps and apps that impact productivity and the user experience; detected as potentially unwanted applications (PUAs)

# Alert suppresion
- Rule suppresion can be created from an existing alert.
- When a suppression rule is created it takes affect on new alerts but does not affect alerts that have already triggered prior to the suppression.

## What is Automated Investigation and Remediation (AIR)
Microsoft security for endpoint includes AIR capabilities, which uses inspection algorithms and is design to examine the alert and take action to resolve breaches.
Automation levels can be set to Full, or Semi-Automation. All remediation actions are tracked in the Action Center.

| Automation Level | Description |
|---|---|
|No Automation | automated  investigations don't run on devices but other threat proctection may still be in effec depending on how AV in configured.
|Full - remediate threats automatically (also referred to as full automation) | With full automation, remediation actions are performed automatically. All remediation actions that are taken can be viewed in the Action Center on the History tab. If necessary, a remediation action can be undone.
|Semi - require approval for any remediation (also referred to as semi-automation) | With this level of semi-automation, approval is required for any remediation action. Such pending actions can be viewed and approved in the Action Center, on the Pending tab.
|Semi - require approval for core folders remediation (also a type of semi-automation) | With this level of semi-automation, approval is required for any remediation actions needed on files or executables that are in core folders. Core folders include operating system directories, such as the Windows (\windows*).Remediation actions can be taken automatically on files or executables that are in other (non-core) folders.Pending actions for files or executables in core folders can be viewed and approved in the Action Center, on the Pending tab.Actions that were taken on files or executables in other folders can be viewed in the Action Center, on the History tab.
|Semi - require approval for non-temp folders remediation (also a type of semi-automation) | With this level of semi-automation, approval is required for any remediation actions needed on files or executables that aren't in temporary folders. Temporary folders can include the following examples:\users*\appdata\local\temp* \documents and settings*\local settings\temp* \documents and settings*\local settings\temporary* ,\windows\temp*,\users*\downloads*,\program files\,\program files (x86)*, \documents and settings*\users*. Remediation actions can be taken automatically on files or executables that are in temporary folders. Pending actions for files or executables that aren't in temporary folders can be viewed and approved in the Action Center, on the Pending tab.

## What is the Action Center?
This center lists the remediation actions that have been completed, are that are pending. This center is related to AIR as this is where you can go manage actions based on the automation level you have selected.
It will have remediation actions for Defender for Endpoint and Defender for Office365.

## What is Advanced Hunting?
Advanced Hunting is a query based threat-hunting tool where you can explore up to 30 days of raw data. To use advanced hunting you need to turn on Microsoft Defender XDR. We can categorize advanced hunting data into two types:
  ### Event or activity data
  These are tables about alerts, security events, system events and assessments.

  ## Entity data
  These are tables with info about users and devices.

- The information in advanced hunting is in UTC zone.

> **Practical note:** I've noticed that the available tables in Advanced Hunting Query vary depending on the environment. However, the below table is a good reference to what tables you can expect to find.

|Table name | Description
|---|---|
|AlertEvidence	| Files, IP addresses, URLs, users, or devices associated with alerts
|AlertInfo	|Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity, including severity information and threat categorization
|CloudAppEvents|	Events involving accounts and objects in Office 365 and other cloud apps and services
|DeviceEvents	|Multiple event types, including events triggered by security controls such as Windows Defender Antivirus and exploit protection
|DeviceFileCertificateInfo	|Certificate information of signed files obtained from certificate verification events on endpoints
|DeviceFileEvents|	File creation, modification, and other file system events
|DeviceImageLoadEvents	|DLL loading events
|DeviceInfo	|Machine information, including OS information
|DeviceLogonEvents	|Sign-ins and other authentication events on devices
|DeviceNetworkEvents	|Network connection and related events
|DeviceNetworkInfo	|Network properties of devices, including physical adapters, IP and MAC addresses, as well as connected networks and domains
|DeviceProcessEvents	|Process creation and related events
|DeviceRegistryEvents	|Creation and modification of registry entries
|DeviceTvmSecureConfigurationAssessment	|Threat & Vulnerability Management assessment events, indicating the status of various security configurations on devices
|DeviceTvmSecureConfigurationAssessmentKB	|Knowledge base of various security configurations used by Threat & Vulnerability Management to assess devices; includes mappings to various standards and benchmarks
|DeviceTvmSoftwareInventory	|Inventory of software installed on devices, including their version information and end-of-support status
|DeviceTvmSoftwareVulnerabilities	|Software vulnerabilities found on devices and the list of available security updates that address each vulnerability
|DeviceTvmSoftwareVulnerabilitiesKB|	Knowledge base of publicly disclosed vulnerabilities, including whether exploit code is publicly available
|EmailAttachmentInfo	|Information about files attached to emails
|EmailEvents	|Microsoft 365 email events, including email delivery and blocking events
|EmailPostDeliveryEvents	|Security events that occur post-delivery, after Microsoft 365 delivered the emails to the recipient mailbox
|EmailUrlInfo	|Information about URLs on emails
|IdentityDirectoryEvents	|Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller.
|IdentityInfo	|Account information from various sources, including Microsoft Entra ID
|IdentityLogonEvents	|Authentication events on Active Directory and Microsoft online services
|IdentityQueryEvents	|Queries for Active Directory objects, such as users, groups, devices, and domains

> **Practical note:** Though Advanced Hunting, I've been able to find information that I was NOT able to easily find using the email Explorer GUI. I worked an incident where the attackers used unicode in the emails Subject line, which made it hard to find other emails with the same subject in the email Explorer GUI. The Advanced Hunting query box took the unicode and I was able to search the EmailEvents table to find what I needed. 
Also note that what you can search in Advanced Hunting can be different than what you can search in the Log Analytics.

## Investigate Microsoft Entra sign-in logs
- The SigninLogs table in the Log Analytics within Sentinel, provides access to the same information you can find in the Azure Portal by going to Microsoft Entra ID --> Monitoring --> Sign-in-logs

## Configure the Microsoft Defender portal
The primary setting for Defender XDR is the notifications email configuration. There are two types:
|Notification Type| Description
|---|---|
| Incidents | When new Incidents are created|
| Threat Analytics | When new Threat Analytic reports are created|
