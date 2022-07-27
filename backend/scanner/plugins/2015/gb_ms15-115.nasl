###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Remote Code Execution Vulnerabilities (3105864)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806157");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6100", "CVE-2015-6101", "CVE-2015-6102", "CVE-2015-6103",
                "CVE-2015-6104", "CVE-2015-6109", "CVE-2015-6113");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-11-11 10:53:23 +0530 (Wed, 11 Nov 2015)");
  script_name("Microsoft Windows Remote Code Execution Vulnerabilities (3105864)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-115.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The way that Windows handles objects in memory. An attacker who successfully
    exploited the vulnerabilities could run arbitrary code in kernel mode.

  - The Windows fails to properly initialize memory addresses, allowing an
    attacker to retrieve information that could lead to a Kernel Address Space
    Layout Randomization (KASLR) bypass.

  - The Adobe Type Manager Library in Windows improperly handles specially
    crafted embedded fonts.

  - The Windows kernel fails to properly validate permissions, allowing an
    attacker to inappropriately interact with the filesystem from low
    integrity level user-mode applications.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to do Kernel Address Space Layout Randomization (KASLR) bypass and execute
  arbitrary code taking complete control of the affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 8/8.1 x32/x64
  Microsoft Edge on Windows 10 x32/x64
  Microsoft Windows Server 2012/R2
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3097877");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101746");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-115");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Ntoskrnl.exe");
if(!dllVer && !exeVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.19525"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "Less than 6.0.6002.19525";
    }

    else if(version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23834"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23834";
    }
  }

  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6002.19514"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "Less than 6.0.6002.19514";
    }

    else if(version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23823"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23823";
    }
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"6.1.7601.19044"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "Less than 6.1.7601.19044";
    }

    else if(version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23249"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "6.1.7601.22000 - 6.1.7601.23249";
    }
  }

  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"6.1.7601.19045"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "Less than 6.1.7601.19045";
    }

    else if(exeVer && version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23249"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "6.1.7601.22000 - 6.1.7601.23249";
    }
  }
}

else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"6.2.9200.17554"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "Less than 6.2.9200.17554";
    }

    else if(version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21670"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21670";
    }
  }

  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"6.2.9200.17557"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "Less than 6.2.9200.17557";
    }

    else if(version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21673"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21673";
    }
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(dllVer && version_is_less(version:dllVer, test_version:"6.3.9600.18093"))
  {
    VULN2 = TRUE ;
    Vulnerable_range = "Less than 6.3.9600.18093";
  }

  else if(exeVer && version_is_less(version:exeVer, test_version:"6.3.9600.18090"))
  {
    VULN3 = TRUE ;
    Vulnerable_range = "Less than 6.3.9600.18090";
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16384"))
  {
    Vulnerable_range = "Less than 10.0.10240.16384";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.2"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.2";
    VULN2 = TRUE ;
  }
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\Win32k.sys" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\system32\Ntoskrnl.exe" + '\n' +
           'File version:     ' + exeVer + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
