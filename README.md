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

## Introduction
Mageni eases for you the vulnerability management cycle. We believe cybersecurity must be an enjoyable and uplifting experience to be truly fulfilling in your life. **Mageni empowers you to identify, prioritize, and respond to vulnerabilities and misconfigurations before they are exploited by hackers.** Mageni takes the discomfort and pain out of cybersecurity by easing simple tasks for vulnerability management, such as:

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
- And more ...

 **Mageni is accessible, powerful, and will save you time, money, and resources while reducing the risk of non compliance, financial losses, fines, and security breaches.** This is what it currently looks like:

<p align="center">
    <img src="https://www.mageni.net/assets/img/macbook.jpeg" width="600" style="padding-top:10px;">
</p>

## Vulnerability Management Statistics
- 60% of breach victims were breached due to an unpatched known vulnerability (Ponemom Institute)
- 62% were unaware that they were vulnerable prior to the data breach (Ponemom Institute)
- $4.24 million cost per data breach on average; highest in 17-year report history (IBM)

## Mission
Mageni's mission is to make your life more enjoyable and peaceful by providing you with a wonderful vulnerability management platform.

## Vision
We envision a world where cybersecurity and vulnerability management is an enjoyable and uplifting experience that is truly fulfilling in your life.

## What is the Vulnerability Management Cycle?

The Vulnerability Management Cycle is intended to allow organizations and individuals to identify and assess computer system security weaknesses; prioritize assets; assess, report, and remediate the weaknesses; and verify that they have been eliminated. **Mageni automates for you the Vulnerability Management Cycle saving you time, money, and resources, and helps you to comply with security standards like PCI DSS, NIST, and others.**

Here you can see the Vulnerability Management Cycle according to Gartner:

<p align="center">
    <img src="https://www.mageni.net/assets/img/vmcycle.jpeg" width="600" style="padding-top:10px;">
</p>

Mageni takes the pain out of the vulnerability management cycle by easing those tasks.

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
- Has Mageni helped your MSP? The sponsorship tier <a href="https://buy.stripe.com/bIY4gE8MY7USgJWdQX">MSP</a> gives you the chance to give back.

### Benefits of Sponsorship
- Access to the private issues repository
- Access to the private discusion board
- Priority support to fix bugs
- Your feature request will be a top priority
- You have an active role in preserving the software that you use

## CompTIA PenTest+ Certification
Mageni is developed by certified CompTIA PenTest+ Professionals. CompTIA PenTest+ is for cybersecurity professionals tasked with penetration testing and vulnerability management, is compliant with ISO 17024 standards and approved by the US DoD. 

## Mageni helps to reduce climate change
Mageni is a member of the <a href="https://climate.stripe.com/nJ22UV" target="_blank">Stripe Climate</a> and contributes 1% of your sponsorship to reduce climate change.

With your sponsorship you are making this world a better place for both present and future generations.

## Contributing
You can also contribute with:

- Bug reports
- Features request

For more information, <a href="https://github.com/mageni/mageni/blob/master/CONTRIBUTING.md">read the contribution guide</a>

## Thank you, open source
Mageni uses a lot of open source projects and we thank them with all our hearts. We hope that providing Mageni as an free, open source project will help other people the same way those softwares have helped us and in doing so Mageni is also in strict compliance with the open source licenses. 

## Thank you, open source
Mageni uses a lot of open source projects and we thank them with all our hearts. We hope that providing Mageni as an free, open source project will help other people the same way those softwares have helped us and in doing so Mageni is also in strict compliance with the open source licenses. 

## Legal
Mageni publishes this open-source software on Github solely for lawful purposes and for education, research and teaching in cybersecurity and computer programming. You must use the software in a manner that complies with all applicable national, federal, state and local laws, statutes, ordinances, regulations, codes, and other types of government authority.

## Fair Use
Mageni publishes this open-source software as fair use of copyrighted work for purposes of education, teaching and research (See 17 U.S.C. § 107).  *“fair use is not just excused by the law, it is wholly authorized by the law.”* Lenz v. Universal Music Corp., 815 F.3d 1145, 1151 (9th Cir. 2016). Mageni is using copyrighted work as authorized by 17 U.S.C. § 107

### DMCA

If you believe that, according to the DMCA, we are missing something, drop us an email to dmca@mageni.net

Before submitting or sending an email, please consult your lawyer, be aware and read the <a href="https://www.copyright.gov/legislation/pl105-304.pdf" target="_blank">DMCA</a>, <a href="https://uscode.house.gov/view.xhtml?path=/prelim@title18/part1/chapter79&edition=prelim" target="_blank">18 U.S. Code § 1621 - Perjury generally</a>, and <a href="https://www.copyright.gov/title17/title17.pdf" target="_blank">US Copyright Law</a>

**The DMCA requires that you swear to the facts in your copyright complaint under penalty of perjury. It is a federal crime to intentionally lie in a sworn declaration. (See U.S. Code, Title 18, Section 1621.) Submitting false, fraudulent, and bad faith information could also result in civil liability — that is, you could get sued and you could be fined or imprisoned not more than five years, or both. The DMCA also provides a remedy for bad-faith takedowns**, specifically:

Any person who knowingly materially misrepresents under this section

1. that material or activity is infringing, or
2. that material or activity was removed or disabled by mistake or misidentification, shall be liable for any damages, including costs and attorneys’ fees, incurred by the alleged infringer, by any copyright owner or copyright owner’s authorized licensee, or by a service provider, who is injured by such misrepresentation, as the result of the service provider relying upon such misrepresentation in removing or disabling access to the material or activity claimed to be infringing, or in replacing the removed material or ceasing to disable access to it.

17 U.S.C.A. § 512

### Free, forever free.

**Mageni does not sells the open source software. This software is, and always will be, free and open source.**

## Disclaimer

Mageni did not obtain this code from reverse engineering. All source code is and was publicly available under <a href="https://opensource.org/licenses/alphabetical">open-source licenses</a>

## License
<a href="https://github.com/mageni/mageni/blob/master/LICENSE.txt" target="_blank">GPLv2</a>
