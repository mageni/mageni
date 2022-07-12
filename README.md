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

# Table of Contents
1. [Introduction](#introduction)
2. [Statistics](#statistics)
3. [About Mageni](#about-mageni)
4. [Audience](#audience)
5. [Install on Linux](#linux)
6. [Install on macOS](#macos)
7. [Install on Windows](#windows)
8. [Sponsorship](#sponsorship)
9. [Thank you, open source](#thank-you-open-source)
9. [License](#license)
10. [Applicable Laws, Legal, Fair Use, and DMCA](#applicable-laws-legal-fair-use-and-dmca)

## Introduction

Mageni is passionate about solving the world's toughest and most complex problems using open-source. 

### Statistics

- **Unpatched and exposed services** account for 82% of successful attack (Tetra Defense)
- 60% of breach victims were breached due to an **unpatched known vulnerability** (Ponemom Institute)
- 62% were **unaware that they were vulnerable** prior to the data breach (Ponemom Institute)
- $4.24 million cost per **data breach** on average; highest in 17-year report history (IBM)

### About Mageni

Mageni provides a free and open-source vulnerability scanner full of delightful features. We believe cybersecurity must be an enjoyable and uplifting experience to be truly fulfilling in your life. Mageni empowers you to identify, prioritize, and respond to vulnerabilities, risky services and misconfigurations before they are exploited by hackers. Mageni is accessible, powerful, and will save you time, money, and resources while reducing the risk of non-compliance, financial losses, fines, and data breaches

Mageni eases simple tasks for vulnerability management, such as:

- Asset Discovery
- Prioritize Assets
- Vulnerability Scanning
- Vulnerability Assessment
- Reporting
- Remediation
- Vulnerability Prioritization
- Vulnerability Validation
- Compliance Testing (PCI DSS, NIST, HIPAA, ISO, NERC, FISMA, NIS)
- Penetration Testing
- Security Audits
- IoT, OT, and SCADA Security Testing
- And more ...

This is what it currently looks like:

<p align="center">
    <img src="https://www.mageni.net/assets/img/macbook.jpeg" width="600" style="padding-top:10px;">
</p>

## Audience
- PenTester
- Cybersecurity Professionals 
- SOC Analyst
- Chief Information Security Officer
- Security Researchers
- Auditors
- Red Team
- Malware Analyst
- Business owners
- System Administrators
- Developers
- And anyone concerned about cybersecurity and vulnerabilities

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
## Sponsorship
We love working on Mageni and give it to you without expecting anything in return. We find great joy in providing you with the best foundation for your vulnerability management program as we possibly can. However, if you choose to show your appreciation by sponsoring this project, know that we are deeply appreciative.

1% of the proceeds go towards reducing climate change on earth.

- Are you using Mageni for your personal projects and side projects and really enjoying it? The sponsorship tier <a href="https://buy.stripe.com/5kA7sQ2oA1wu9hu7sy">Enthusiast</a> gives you the chance to give back. 
- Has Mageni reinvigorated your love for cybersecurity? The sponsorship tier <a href="https://buy.stripe.com/aEU9AY3sE5MK8dq14g">Lover</a> gives you the chance to give back. 
- Has Mageni helped you in your career and made your cybersecurity experience more enjoyable? The sponsorship tier <a href="https://buy.stripe.com/00g4gE8MYdfc79mbIT">Professional</a> gives you the chance to give back. 
- Has Mageni helped your small business (less than 100 employees)? The sponsorship tier <a href="https://buy.stripe.com/aEUbJ6fbm1wudxK28i">Small Business</a> gives you the chance to give back. 
- Has Mageni helped your medium business (less than 500 employees)? The sponsorship tier <a href="https://buy.stripe.com/00gfZmaV6fnkbpC4gp">Medium Business</a> gives you the chance to give back. 
- Has Mageni helped your organization (more than 500 employees)? The sponsorship tier <a href="https://buy.stripe.com/28ocNa1kwfnk0KYbIQ">Organization</a> gives you the chance to give back. 

### Benefits of Sponsorship
- Access to the private issues repository
- Access to the private discusion board
- Priority support to fix bugs
- Your feature request will be a top priority
- You have an active role in preserving the software that you use

## Contributing
You can also contribute with:

- Bug reports
- Features request

For more information, <a href="https://github.com/mageni/mageni/blob/master/CONTRIBUTING.md">read the contribution guide</a>

## Thank you, open source
Mageni uses a lot of open source projects and we thank them with all our hearts. We hope that providing Mageni as an free, open source project will help other people the same way those softwares have helped us and in doing so Mageni is also in strict compliance with the open source licenses. 

Mageni is an important open source contribution to the upstream projects as it provides a moderm web interface and EDA which was really missing to the open source community.

## License
<a href="https://github.com/mageni/mageni/blob/master/LICENSE.txt" target="_blank">GPLv2</a>

## Applicable Laws, Legal, Fair Use, and DMCA
Mageni publishes open-source software on Github solely for lawful purposes and for education, research and teaching in cybersecurity and computer programming. You must use the software in a manner that complies with all applicable national, federal, state and local laws, statutes, ordinances, regulations, codes, and other types of government authority.

If you have questions about the GPL license, copyrights law, DMCA, our DMCA designated agent, and other legal stuff. Please <a href="https://github.com/mageni#legal-copyrights-dmca-and-fair-use">go to our legal section on GitHub</a>