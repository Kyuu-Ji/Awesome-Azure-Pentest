# Awesome Azure Penetration Testing

A curated list of useful tools and resources for penetration testing and securing Microsofts cloud platform **Azure**.

## Table of Contents

- [Tools](#tools)
  - [Enumeration](#enumeration)
  - [Information Gathering](#information-gathering)
  - [Lateral Movement](#lateral-movement)
  - [Exploitation](#exploitation)
    - [Credential Attacks](#credential-attacks)
- [Resources](#resources)
  - [Articles](#articles)
    - [Lists and Cheat Sheets](#lists-and-cheat-sheets)
  - [Lab Exercises](#lab-exercises)
  - [Talks & Videos](#talks-and-videos)
  - [Books](#books)
  - [Tips and Tricks](#tips-and-tricks)

## Tools

### Enumeration

- [o365creeper](https://github.com/LMGsec/o365creeper) - Enumerate valid email addresses
- [CloudBrute](https://github.com/0xsha/CloudBrute) - Tool to find a cloud infrastructure of a company on top Cloud providers
- [cloud_enum](https://github.com/initstring/cloud_enum) - Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud
- [Azucar](https://github.com/nccgroup/azucar) - Security auditing tool for Azure environments
- [CrowdStrike Reporting Tool for Azure (CRT)](https://github.com/CrowdStrike/CRT) - Query Azure AD/O365 tenants for hard to find permissions and configuration settings
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool. Security posture assessment of different cloud environments.
- [BlobHunter](https://github.com/cyberark/blobhunter) - A tool for scanning Azure blob storage accounts for publicly opened blobs
- [Grayhat Warfare](https://buckets.grayhatwarfare.com/) - Open Azure blobs and AWS bucket search
- [Office 365 User Enumeration](https://github.com/gremwell/o365enum) - Enumerate valid usernames from Office 365 using ActiveSync, Autodiscover v1 or office.com login page
- [CloudFox](https://github.com/BishopFox/cloudfox) - Automating situational awareness for cloud penetration tests
- [Monkey365](https://github.com/silverhack/monkey365) - Conduct Microsoft 365, Azure subscriptions and Azure Active Directory security configuration reviews
- [Azure-AccessPermissions](https://github.com/csandker/Azure-AccessPermissions) - PowerShell script to enumerate access permissions in an Azure AD environment
- [Prowler](https://github.com/prowler-cloud/prowler) - Perform AWS and Azure security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness

### Information Gathering

- [o365recon](https://github.com/nyxgeek/o365recon) - Information gathering with valid credentials to Azure
- [Get-MsolRolesAndMembers.ps1](https://gist.github.com/ciphertxt/2036e614edf4bf920796059017fbbc3d) - Retrieve list of roles and associated role members
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Framework to interact with Azure AD
- [PowerZure](https://github.com/hausec/PowerZure) - PowerShell framework to assess Azure security
- [Azurite](https://github.com/FSecureLABS/Azurite) - Enumeration and reconnaissance activities in the Microsoft Azure Cloud
- [Sparrow.ps1](https://github.com/cisagov/Sparrow) - Helps to detect possible compromised accounts and applications in the Azure/M365 environment
- [Hawk](https://github.com/T0pCyber/hawk) - Powershell based tool for gathering information related to O365 intrusions and potential breaches
- [Microsoft Azure AD Assessment](https://github.com/AzureAD/AzureADAssessment) - Tooling for assessing an Azure AD tenant state and configuration
- [Cloud Katana](https://github.com/Azure/Cloud-Katana) - Unlocking Serverless Computing to Assess Security Controls
- [SCuBA M365 Security Baseline Assessment Tool](https://github.com/cisagov/ScubaGear) - Automation to assess the state of your M365 tenant against CISA's baselines

### Lateral Movement

- [Stormspotter](https://github.com/Azure/Stormspotter) - Azure Red Team tool for graphing Azure and Azure Active Directory objects
- [AzureADLateralMovement](https://github.com/talmaor/AzureADLateralMovement) - Lateral Movement graph for Azure Active Directory
- [SkyArk](https://github.com/cyberark/SkyArk) - Discover, assess and secure the most privileged entities in Azure and AWS
- [omigood (OM I GOOD?)](https://github.com/marcosimioni/omigood) - Scanner to detect VMs vulnerable to one of the "OMIGOD" vulnerabilities

### Exploitation

- [MicroBurst](https://github.com/NetSPI/MicroBurst) - A collection of scripts for assessing Microsoft Azure security
- [azuread_decrypt_msol_v2.ps1](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c) - Decrypt Azure AD MSOL service account
- [Microsoft-Teams-GIFShell](https://github.com/bobbyrsec/Microsoft-Teams-GIFShell) - Microsoft Teams can be leveraged by an attacker, to execute a reverse shell between an attacker and victim piped through malicious GIFs sent in Teams messages

#### Credential Attacks

- [MSOLSpray](https://github.com/dafthack/MSOLSpray) - A password spraying tool for Microsoft Online accounts (Azure/O365)
- [MSOLSpray.py](https://github.com/MartinIngesen/MSOLSpray) - A Python version of the MSOLSpray password spraying tool for Microsoft Online accounts (Azure/O365)
- [o365spray](https://github.com/0xZDH/o365spray) - Username enumeration and password spraying tool aimed at Microsoft O365
- [MFASweep](https://github.com/dafthack/MFASweep) -  A tool for checking if MFA is enabled on multiple Microsoft Services Resources
- [adconnectdump](https://github.com/fox-it/adconnectdump) - Dump Azure AD Connect credentials for Azure AD and Active Directory

## Resources

### Articles

- [Abusing Azure AD SSO with the Primary Refresh Token ](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
- [Abusing dynamic groups in Azure AD for Privilege Escalation](https://www.mnemonic.no/blog/abusing-dynamic-groups-in-azure/)
- [Attacking Azure, Azure AD, and Introducing PowerZure](https://hausec.com/2020/01/31/attacking-azure-azure-ad-and-introducing-powerzure/)
- [Attacking Azure & Azure AD, Part II](https://posts.specterops.io/attacking-azure-azure-ad-part-ii-5f336f36697d)
- [Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- [Azure AD Introduction for Red Teamers](https://www.synacktiv.com/posts/pentest/azure-ad-introduction-for-red-teamers.html)
- [Azure AD Pass The Certificate](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)
- [Azure AD privilege escalation - Taking over default application permissions as Application Admin](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/)
- [Defense and Detection for Attacks Within Azure](https://posts.specterops.io/detecting-attacks-within-azure-bdc40f8c0766)
- [Hunting Azure Admins for Vertical Escalation](https://www.lares.com/blog/hunting-azure-admins-for-vertical-escalation/)
- [Impersonating Office 365 Users With Mimikatz](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
- [Lateral Movement from Azure to On-Prem AD](https://posts.specterops.io/death-from-above-lateral-movement-from-azure-to-on-prem-ad-d18cb3959d4d)
- [Malicious Azure AD Application Registrations](https://www.lares.com/blog/malicious-azure-ad-application-registrations/)
- [Moving laterally between Azure AD joined machines](https://medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines-ed1f8871da56)
- [CrowdStrike Launches Free Tool to Identify and Help Mitigate Risks in Azure Active Directory](https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/)
- [Privilege Escalation Vulnerability in Azure Functions](https://www.intezer.com/blog/cloud-security/royal-flush-privilege-escalation-vulnerability-in-azure-functions/)
- [Azure Application Proxy C2](https://www.trustedsec.com/blog/azure-application-proxy-c2/)
- [Recovering Plaintext Passwords from Azure Virtual Machines like It’s the 1990s](https://www.guardicore.com/labs/recovering-plaintext-passwords-azure/)
- [Forensicating Azure VMs](https://isc.sans.edu/forums/diary/Forensicating+Azure+VMs/27136/)
- [Network Forensics on Azure VMs](https://isc.sans.edu/forums/diary/Network+Forensics+on+Azure+VMs+Part+1/27536/)
- [Cross-Account Container Takeover in Azure Container Instances](https://unit42.paloaltonetworks.com/azure-container-instances/)
- [Azure Active Directory password brute-forcing flaw](https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/)
- [How to Detect Azure Active Directory Backdoors: Identity Federation](https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html)
- [Azure App Service vulnerability exposed hundreds of source code repositories](https://blog.wiz.io/azure-app-service-source-code-leak/)
- [AutoWarp: Cross-Account Vulnerability in Microsoft Azure Automation Service](https://orca.security/resources/blog/autowarp-microsoft-azure-automation-service-vulnerability/)
- [Microsoft Azure Synapse Pwnalytics](https://medium.com/tenable-techblog/microsoft-azure-synapse-pwnalytics-87c99c036291)
- [Microsoft Azure Site Recovery DLL Hijacking](https://medium.com/tenable-techblog/microsoft-azure-site-recovery-dll-hijacking-cd8cc34ef80c)
- [FabriXss (CVE-2022-35829): Abusing a Custom Role User Using CSTI and Stored XSS in Azure Fabric Explorer](https://orca.security/resources/blog/fabrixss-vulnerability-azure-fabric-explorer/)
- [Untangling Azure Active Directory Principals & Access Permissions](https://csandker.io/2022/10/19/Untangling-Azure-Permissions.html)
- [How to Detect OAuth Access Token Theft in Azure](https://www.inversecos.com/2022/08/how-to-detect-oauth-access-token-theft.html)
- [How to deal with Ransomware on Azure](https://sysdig.com/blog/ransomware-azure-mitigations/)
- [How Orca found Server-Side Request Forgery (SSRF) Vulnerabilities in four different Azure Services](https://orca.security/resources/blog/ssrf-vulnerabilities-in-four-azure-services/)
- [EmojiDeploy: Smile! Your Azure web service just got RCE’d](https://ermetic.com/blog/azure/emojideploy-smile-your-azure-web-service-just-got-rced)
- [Bounce the Ticket and Silver Iodide on Azure AD Kerberos](https://www.silverfort.com/resources/white-paper/bounce-the-ticket-and-silver-iodide-on-azure-ad-kerberos/)

#### Lists and Cheat Sheets

- [List of all Microsoft Portals](https://msportals.io/)
- [Azure Articles from NetSPI](https://blog.netspi.com/?s=azure)
- [Azure Cheat Sheet on CloudSecDocs](https://cloudsecdocs.com/azure/services/overview/)
- [Resources about Azure from Cloudberry Engineering](https://cloudberry.engineering/tags/azure/)
- [Resources from PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)
- [Encyclopedia on Hacking the Cloud](https://hackingthe.cloud/)
- [Azure AD - Attack and Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
- [Azure Security Resources and Notes](https://github.com/rootsecdev/Azure-Red-Team)
- [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/)

### Lab Exercises

- [azure-security-lab](https://github.com/azurecitadel/azure-security-lab) - Securing Azure Infrastructure - Hands on Lab Guide
- [AzureSecurityLabs](https://github.com/davisanc/AzureSecurityLabs) - Hands-on Security Labs focused on Azure IaaS Security
- [Building Free Active Directory Lab in Azure](https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f)
- [Aria Cloud Penetration Testing Tools Container](https://github.com/iknowjason/AriaCloud) - A Docker container for remote penetration testing
- [PurpleCloud](https://github.com/iknowjason/PurpleCloud) - Multi-use Hybrid + Identity Cyber Range implementing a small Active Directory Domain in Azure alongside Azure AD and Azure Domain Services
- [BlueCloud](https://github.com/iknowjason/BlueCloud) - Cyber Range system with a Windows VM for security testing with Azure and AWS Terraform support
- [Azure Red Team Attack and Detect Workshop](https://github.com/mandiant/Azure_Workshop)
- [SANS Workshop – Building an Azure Pentest Lab for Red Teams](https://www.sans.org/webcasts/sans-workshop-building-azure-pentest-lab-red-teams/) - The link in the description contains a password-protected OVA file that can be used until 2nd March 2024

### Talks and Videos

- [Attacking and Defending the Microsoft Cloud (Office 365 & Azure AD](https://www.youtube.com/watch?v=SG2ibjuzRJM)
  - [Presentation Slides](https://i.blackhat.com/USA-19/Wednesday/us-19-Metcalf-Attacking-And-Defending-The-Microsoft-Cloud.pdf)
- [TR19: I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory](https://www.youtube.com/watch?v=JEIR5oGCwdg)
  - [Presentation Slides](https://troopers.de/downloads/troopers19/TROOPERS19_AD_Im_in_your_cloud.pdf)
- [Dirk Jan Mollema - Im In Your Cloud Pwning Your Azure Environment - DEF CON 27 Conference](https://www.youtube.com/watch?v=xei8lAPitX8)
  - [Presentation Slides](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Dirk-jan-Mollema-Im-in-your-cloud-pwning-your-azure-environment.pdf)
- [Adventures in Azure Privilege Escalation Karl Fosaaen](https://www.youtube.com/watch?v=EYtw-XPml0w)
  - [Presentation Slides](https://notpayloads.blob.core.windows.net/slides/Azure-PrivEsc-DerbyCon9.pdf)
- [Introducing ROADtools - Azure AD exploration for Red Teams and Blue Teams](https://www.youtube.com/watch?v=o5QDt30Pw_o)

### Books

- [Pentesting Azure Applications](https://nostarch.com/azure)

### Tips and Tricks

- Replace COMPANYNAME with the company name of your choice to check if they use Azure. If the **NameSpaceType** indicates _"Managed"_, then the company is using Azure AD:
```
https://login.microsoftonline.com/getuserrealm.srf?login=username@COMPANYNAME.onmicrosoft.com&xml=1
```

