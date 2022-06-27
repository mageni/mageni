<p align="center">
    <img src="https://www.mageni.net/assets/img/githublogo.jpeg" width="100">
</p>

<p align="center">
<a href="https://bestpractices.coreinfrastructure.org/projects/6196">
    <img src="https://bestpractices.coreinfrastructure.org/projects/6196/badge">
</a>
<a href="https://www.codacy.com/gh/mageni/mageni/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=mageni/mageni&amp;utm_campaign=Badge_Grade">
    <img src="https://app.codacy.com/project/badge/Grade/558c9a5a09074cc293aef32ed6cee6b2"/>
</a>
<a href="https://codeclimate.com/github/mageni/mageni/maintainability"><img src="https://api.codeclimate.com/v1/badges/6f48e5542ead5e70f9fe/maintainability" /></a>
<a href="https://github.com/mageni/mageni/actions/workflows/codeql-analysis.yml"><img src="https://github.com/mageni/mageni/actions/workflows/codeql-analysis.yml/badge.svg" /></a>
<a href="https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html"><img src="https://img.shields.io/badge/License-GPL_v2-blue.svg" /></a>
</p>

<br />

## Introduction
Mageni eases for you the vulnerability management cycle. We believe cybersecurity must be an enjoyable and uplifting experience to be truly fulfilling in your life. Mageni takes the discomfort and pain out of cybersecurity by easing simple tasks for vulnerability management, such as:

- Asset
    - Discovery
    - Prioritization
- Vulnerability 
    - Scanning
    - Assessment
    - Reporting
    - Remediation
    - Prioritization
    - Validation
    - Exception 
- Testing
    - Hardening
    - Compliance
        - PCI DSS
        - NIST CSF
        - HIPAA
        - ISO
        - NERC
        - FISMA
        - NIS Directive
- Intelligence
    - VirusTotal 
    - CISA Known Exploited Vulnerabilities Catalog
    - MITRE ATT&CK
- Security Audits
    - Network
    - Servers
    - Desktops
    - Applications
    - Services
    - Ports
- Notifications 
    - Email with zero-configuration
    - Microsoft Teams *Coming soon*
    - SMS *Coming soon*
    - Twitter *Coming soon*
    - Webhooks *Coming soon*
- Scoring
    - CVSSv2
    - CVSSv3.1
- Integrations
    - Syslog *Coming soon*
    - SysAid *Coming soon*
    - ServiceNow *Coming soon*
    - SIEM *Coming soon*
- And more features are coming...

Mageni is accessible, powerful, and will **save you time, money, and resources** while reducing the risk of non compliance, financial losses, fines, jail, sanctions, and security breaches. This is what it currently looks like:

<p align="center">
    <img src="https://www.mageni.net/assets/img/macbook.jpeg" width="600" style="padding-top:10px;">
</p>

## Mission
Mageni's mission is to make your life more enjoyable and peaceful by providing you with a wonderful vulnerability management platform.

## Vision
We envision a world where cybersecurity and vulnerability management is an enjoyable and uplifting experience that is truly fulfilling in your life.

## Audience
- PenTester
- Cybersecurity Professionals 
- SOC Analyst
- Chief Information Security Officer
- Security Researchers
- Auditors
- Red Team
- Malware Analyst
- And more ...

## What is the Vulnerability Management Cycle?

The Vulnerability Management Cycle is intended to allow organizations to identify and assess computer system security weaknesses; prioritize assets; assess, report, and remediate the weaknesses; and verify that they have been eliminated. Mageni eases for you the Vulnerability Management Cycle.

Here you can see the Vulnerability Management Cycle according to Gartner:

<p align="center">
    <img src="https://www.mageni.net/assets/img/vmcycle.jpeg" width="600" style="padding-top:10px;">
</p>

Mageni takes the pain out of the vulnerability management cycle by easing those tasks.

## Installation 

### Linux

1. Download Multipass
```
sudo snap install multipass
```
2. Launch a multipass instance
```
multipass launch -c 2 -m 6G -d 20G -n mageni 20.04 && multipass shell mageni
```
3. Install Mageni
```
curl -sL https://www.mageni.net/installation | sudo bash
```

### macOS

1. If you don’t have it already, install Brew. Then, to install Multipass simply execute:
```
brew install --cask multipass
```
2. Launch a multipass instance
```
multipass launch -c 2 -m 6G -d 20G -n mageni 20.04 && multipass shell mageni
```
3. Install Mageni
```
curl -sL https://www.mageni.net/installation | sudo bash
```

### Windows

1. Download the  <a href="https://multipass.run/download/windows" target="_blank">Multipass</a> installer for Windows
```
Note: You need Windows 10 Pro/Enterprise/Education v 1803 or later, or any Windows 10 with VirtualBox
```
2. Ensure your network is private
```
Make sure your local network is designated as private, otherwise Windows prevents Multipass from starting.
```
3. Run the installer
```
You need to allow the installer to gain Administrator privileges.
```
4. Launch a multipass instance
```
multipass launch -c 2 -m 6G -d 20G -n mageni 20.04
```
5. Log into the multipass instance
```
multipass shell mageni
```
6. Install Mageni
```
curl -sL https://www.mageni.net/installation | sudo bash
```

## Contributing
Thank you for considering contributing to Mageni! If you want to contribute, <a href="https://github.com/mageni/mageni/blob/master/CONTRIBUTING.md">read the contribution guide</a>

## Thank you, open source
Mageni uses a lot of open source projects and we thank them with all our hearts. We hope that providing Mageni as an free, open source project will help other people the same way those softwares have helped us. In this repository you will find the Software Bill of Materials (SBOM). <a href="https://www.mageni.net/opensource" target="_blank">This website</a> has the list of all open source software that Mageni uses and their copyrights. If you believe that we are missing something, drop us an email to legal@mageni.net and ASAP we will fix it.

**Please note that Mageni does not sells the open source software. The software is, and always will be, free.**

## Legal
This open source software is provided solely for lawful purposes and use. You must use the software in a manner that complies with all applicable national, federal, state and local laws, statutes, ordinances, regulations, codes and other types of government authority.
