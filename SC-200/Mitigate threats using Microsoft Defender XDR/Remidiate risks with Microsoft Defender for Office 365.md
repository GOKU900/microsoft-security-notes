# Remediate risks with Microsoft Defender for Office 365

## What is Microsoft Defender for Office 365?
Microsoft Defender for Office 365 is an email filtering system that includes features to protect from harmful links. You can do automated responses, and also training & awareness.
- It is a cloud based email protection that can protect on-pre, Exchange Servers or other SMPT email solutions.
- Can be enabled to protect Exchange Online cloud-hosted mailboxes.
- You can also do a hybrid deployment where are protect both on-prem and cloud mailboxes.

## AIR in Microsoft Defender for Office 365
The available automatic remediation actions by the Auto Investigation and Response module in Office 365:

  - Soft delete email messages and clusters (recall that soft deletes are reversable).
  - Block URL (Time of click)
  - Turn off external mail forwarding (useful when we have a compromised account and the attacker has created inbox rules to forward messages to an external email)
  - Turn off delegation (A delagate is an account that has been granted access to another account. A delegate can have permissions ro read, createm or change items in a mailbox. For example, say we have Laura who is a CEO and Jeff who is her assistant. We can make Jeff a delegate of Lauras mailbox so that he can assist her in answering emails, manage her calendar, ect.. In the case of an attack we want to turn off delegation in order to reduce what the attacker has access to.)

Policies for O365 can be configured in the Defender portal.

## Safe Attachments
Protects against unknown malware via machine learning and other analysis techniques. You can select the policy for safe attachments in Defender.

![safe attachment policy selection in Defender for O365.](https://learn.microsoft.com/en-us/training/wwl/m365-threat-remediate/media/new-safe-attachments-policy.png)

Once these settings are configured you can target users with the policy by specific domain, username, or group membership or a combo of them. You can also add exceptions, like for example, you don't want to skip safe attachment filtering and scanning for internal messages (I would not recommend this!).

> **Practical note:** I have seen cases where users are being migrated to different domains and there are forwarding rules setup to send the email to their new inbox. There are cases where malicious emails have been forwarded from their old mailbox to their new one.

## Safe Links

Th O365 Safe Links feature protects users from malicious URLs both in emails and in Office documents. These safe links are client and location agnostic meaning that the location and device of the user doesn't affect the protection.

The following options can be configured as part of the Safe Links policy:

- For Select the action for unknown potentially malicious URLs in messages, selecting On will allow URLs to be rewritten and checked.
Use Safe Attachments to scan downloadable content will enable URL detection to scan files hosted on web sites. For example, if an email contains a link such as https://contoso.com/maliciousfile.pdf, the .pdf file is opened in a separate hypervisor environment and, if the file is found to be malicious, users will see a warning page if they select the link.

- Apply safe links to messages sent within the organization will provide the same level of protection when links are sent by email within the organization.
- 
 -Do not track when users click safe links enables or disables storing Safe Links select data for clicked URLs. Microsoft recommends leaving this setting unselected, which enables tracking for clicked URLs.
  
 -Do not allow users to click through to the original URL will prevent users from proceeding to the target web site if it's found to be malicious.
 
-If users frequently receive links from web sites that are known to be safe, you can enter those URLs under Do not rewrite the following URL. For example, you might add the URL to a partner's website if users frequently receive emails from the partner that include URLs to the external organization's website.

![Safe Links Policy](https://learn.microsoft.com/en-us/training/wwl/m365-threat-remediate/media/new-safe-links-policy.png#lightbox)

## Anti-phishing policies
Incoming emails are evaluated by multiple machine learning models. Actions are taken based on the configured policy. It includes
- Impersonation
- Spoofing


