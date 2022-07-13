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
1. [About Mageni](#about-mageni)
2. [Audience](#audience)
3. [Install on Linux](#linux)
4. [Install on macOS](#macos)
5. [Install on Windows](#windows)
6. [Contributing](#contributing)
7. [Thank you, open source](#thank-you-open-source)
8. [License](#license)
9. [Applicable Laws, Legal, Fair Use, and DMCA](#applicable-laws-legal-fair-use-and-dmca)

## About Mageni

Mageni is a free and open-source vulnerability scanner full of delightful features. We believe cybersecurity must be an enjoyable and uplifting experience to be truly fulfilling in your life. Mageni empowers you to identify, prioritize, and respond to vulnerabilities, risky services and misconfigurations before they are exploited by hackers. Mageni is accessible, powerful, and will save you time, money, and resources while reducing the risk of non-compliance, financial losses, fines, and data breaches

Mageni eases for you simple tasks for vulnerability management, such as:

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

## Contributing
We love working on Mageni and give it to you without expecting anything in return. We find great joy in providing you with the best foundation for your vulnerability management program as we possibly can.

You can contribute with:

- Bug reports
- Features request

For more information, <a href="https://github.com/mageni/mageni/blob/master/CONTRIBUTING.md">read the contribution guide</a>

Send your bug reports and features request to help@mageni.net

## Thank you, open source
Mageni uses a lot of open source projects and we thank them with all our hearts. We hope that providing Mageni as an free, open source project will help other people the same way those softwares have helped us and in doing so Mageni is also in strict compliance with the open source licenses. 

Mageni is an important open source contribution to the upstream projects as it provides a moderm web interface and EDA which was really missing to the open source community.

## License
<a href="https://github.com/mageni/mageni/blob/master/LICENSE.txt" target="_blank">GPLv2</a>

## Applicable Laws, Legal, Fair Use, and DMCA
Mageni publishes open-source software on Github solely for lawful purposes and for education, research and teaching in cybersecurity and computer programming. You must use the software in a manner that complies with all applicable national, federal, state and local laws, statutes, ordinances, regulations, codes, and other types of government authority.

If you have questions about the GPL license, copyrights law, DMCA, our DMCA designated agent, and other legal stuff. Please <a href="https://github.com/mageni#legal-copyrights-dmca-and-fair-use">go to our legal section on GitHub</a>