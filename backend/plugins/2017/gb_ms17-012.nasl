###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (4013078)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810593");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0007", "CVE-2017-0016", "CVE-2017-0039", "CVE-2017-0057",
                "CVE-2017-0100", "CVE-2017-0104");
  script_bugtraq_id(96018, 95969, 96024, 96695, 96700, 96697);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 08:10:02 +0530 (Wed, 15 Mar 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (4013078)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-012.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The Device Guard does not properly validate certain elements of a signed
    PowerShell script.

  - An improper handling of certain requests sent by a malicious SMB server
    to the client.

  - Microsoft Windows fails to properly validate input before loading certain
    dynamic link library (DLL) files.

  - Windows dnsclient fails to properly handle requests.

  - A DCOM object in Helppane.exe configured to run as the interactive user
    fails to properly authenticate the client.

  - iSNS Server service fails to properly validate input from the client,
    leading to an integer overflow.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass security, obtain sensitive information, run arbitrary code,
  cause the affected system to stop responding until it is manually restarted,
  take control of the affected system. An attacker could then:

  - install programs

  - view, change, or delete data

  - create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows 10 x32/x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows 10 Version 1607 x32/x64

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows Server 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4013078");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-012");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-012");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, winVistax64:3,
                   win2008x64:3, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

gdiVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Gdi32.dll");
lmVer = fetch_file_version(sysPath:sysPath, file_name:"System32\IME\IMEJP10\Imjppdmg.exe");

if(!lmVer && !gdiVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && gdiVer)
{
  ## Presently GDR information is not available.
  if(version_is_less(version:gdiVer, test_version:"6.1.7601.23688"))
  {
    Vulnerable_range1 = "Less than 6.1.7601.23688";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0 && lmVer)
{
  if(version_is_less(version:lmVer, test_version:"10.0.6002.19729"))
  {
    Vulnerable_range = "Less than 10.0.6002.19729";
    VULN = TRUE ;
  }

  else if(version_in_range(version:lmVer, test_version:"10.0.6002.24000", test_version2:"10.0.6002.24051"))
  {
    Vulnerable_range = "10.0.6002.24000 - 10.0.6002.24051";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && gdiVer)
{
  if(version_is_less(version:gdiVer, test_version:"6.2.9200.22082"))
  {
     Vulnerable_range1 = "Less than 6.2.9200.22082";
     VULN1 = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && gdiVer)
{
  if(version_is_less(version:gdiVer, test_version:"6.3.9600.18592"))
  {
    Vulnerable_range1 = "Less than 6.3.9600.18592";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && gdiVer)
{
  if(version_is_less(version:gdiVer, test_version:"10.0.10240.17319"))
  {
    Vulnerable_range1 = "Less than 10.0.10240.17319";
    VULN1 = TRUE;
  }

  else if(version_in_range(version:gdiVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.838"))
  {
    Vulnerable_range1 = "10.0.10586.0 - 10.0.10586.838";
    VULN1 = TRUE ;
  }

  else if(version_in_range(version:gdiVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.205"))
  {
    Vulnerable_range1 = "10.0.14393.0 - 10.0.14393.205";
    VULN1 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Gdi32.dll" + '\n' +
           'File version:     ' + gdiVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\IME\IMEJP10\Imjppdmg.exe" + '\n' +
           'File version:     ' + lmVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);