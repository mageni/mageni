###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Graphics Component Remote Code Execution Vulnerability (3089656)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805979");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-2506", "CVE-2015-2507", "CVE-2015-2508", "CVE-2015-2510",
                "CVE-2015-2511", "CVE-2015-2512", "CVE-2015-2517", "CVE-2015-2518",
                "CVE-2015-2527", "CVE-2015-2529", "CVE-2015-2546");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-09-09 15:01:49 +0530 (Wed, 09 Sep 2015)");
  script_name("Microsoft Windows Graphics Component Remote Code Execution Vulnerability (3089656)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-097.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An unspecified error in the Windows Adobe Type Manager Library which
    improperly handles specially crafted OpenType fonts.

  - An unspecified error in Windows Adobe Type Manager Library which fails
    to properly handle objects in memory.

  - Multiple errors in Windows kernel-mode driver which fails to properly
    handle objects in memory.

  - An unspecified error in the Windows kernel mode driver (Win32k.sys) which
    fails to properly validate and enforce integrity levels during certain
    process initialization scenarios.

  - An error in Windows kernel which fails to properly initialize a memory
    address.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to do Kernel Address Space Layout Randomization (KASLR) bypass and execute
  arbitrary code taking complete control of the affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 8/8.1 x32/x64
  Microsoft Windows 10 x32/x64
  Microsoft Windows Server 2012/R2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3086255");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3087039");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3087135");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-097");

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

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\Drivers\Secdrv.sys");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"system32\Gdiplus.dll");
if(!dllVer1 && !dllVer2 && !dllVer3){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2,
      win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"4.3.86.0"))
  {
    VULN1 = TRUE ;
    Vulnerable_range = "Less than 4.3.86.0";
  }
}

##For file = Win32k.sys
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.0.6002.19484"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "Less than 6.0.6002.19484";
    }

    if(version_in_range(version:dllVer2, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23794"))
    {
      VULN2 = TRUE ;
      Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23794";
    }
  }

  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"5.2.6002.19466"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "Less than 5.2.6002.19466";
    }

    if(version_in_range(version:dllVer3, test_version:"6.0.6002.23000", test_version2:"5.2.6002.23774"))
    {
      VULN3 = TRUE ;
      Vulnerable_range = "6.0.6002.23000 - 5.2.6002.23774";
    }
  }
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"6.1.7601.18985"))
  {
    VULN2 = TRUE ;
    Vulnerable_range = "Less than 6.1.7601.18985";
  }

  if(version_in_range(version:dllVer2, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23187"))
  {
    VULN2 = TRUE ;
    Vulnerable_range = "6.1.7601.22000 - 6.1.7601.23187";
  }
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"6.2.9200.17499"))
  {
    VULN2 = TRUE ;
    Vulnerable_range = "Less than 6.2.9200.17499";
  }

  if(version_in_range(version:dllVer2, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21611"))
  {
    VULN2 = TRUE ;
    Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21611";
  }
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"6.3.9600.18045"))
  {
    VULN2 = TRUE ;
    Vulnerable_range = "Less than 6.3.9600.18045";
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"10.0.10240.16384"))
  {
    Vulnerable_range = "Less than 10.0.10240.16384";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\system32\Drivers\Secdrv.sys" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\Win32k.sys" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}

if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\system32\Gdiplus.dll" + '\n' +
           'File version:     ' + dllVer3 + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}
exit(0);
