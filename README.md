<p align="center">
    <a href="https://www.mageni.net" target="_blank">
        <img src="https://pbs.twimg.com/profile_images/1168687855520141312/wrdNG6ne_400x400.png" width="100">
    </a>
</p>

<p align="center">
    <a href="https://www.mageni.net" target="_blank">
        <img src="https://www.mageni.net/assets/img/screenshot.png" width="600" height="300">
    </a>
</p>

## About
Mageni automates for you the vulnerability scanning, assessment, and management process. This saves you time, money, and resources, and helps you achieve compliance with regulations and security standards while mitigating the risk of financial losses and security breaches.

## Audience
- PenTester
- Cybersecurity Professionals 
- SOC Analyst
- Chief Information Security Officer
- Security Researchers
- Auditors
- Red Team

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
## Professional and Enterprise Editions
Mageni also provides a professional an enterprise product with more features like Schedules, Notifications, Migrations and more. 

## Contributing
Thank you for considering contributing to Mageni! The contribution guide can be found in CONTRIBUTING.md

## Thank you, open source
Mageni uses a lot of open source projects and we thank them with all our hearts. We hope that providing Mageni as an free, open source project will help other people the same way those softwares have helped us. For the SBOM and a list of all open source software that Mageni uses and their copyrights, please visit this <a href="https://www.mageni.net/opensource" target="_blank">website</a>