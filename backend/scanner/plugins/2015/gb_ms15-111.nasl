###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Privilege Elevation Vulnerabilities (3096447)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805762");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-2549", "CVE-2015-2550", "CVE-2015-2552", "CVE-2015-2553",
                "CVE-2015-2554");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-14 10:44:11 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Privilege Elevation Vulnerabilities (3096447)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-111.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to windows kernel
  is not handling objects in memory properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to gain privileges via a crafted application.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64
  Microsoft Windows 10 x32/x64
  Microsoft Windows Server 2012/R2
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3088195");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-111");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1,
                   win2012:1,win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Ntoskrnl.exe");
if(!exeVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.0.6002.19503")){
    Vulnerable_range = "Version Less than - 6.0.6002.19503";
    VULN = TRUE ;
  }
  else if(version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23812"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23812";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7601.19018")){
     Vulnerable_range = "Version Less than - 6.1.7601.19018";
     VULN = TRUE ;
  }
  else if(version_in_range(version:exeVer, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23222")){
   Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23222";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.2.9200.17528")){
    Vulnerable_range = "Version Less than - 6.2.9200.17528";
    VULN = TRUE ;
  }
  else if(version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21644"))
  {
    Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21644";
    VULN = TRUE ;
  }
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.3.9600.18066"))
  {
    Vulnerable_range = "Version Less than - 6.3.9600.18066";
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"10.0.10240.16545"))
  {
    Vulnerable_range = "Less than 10.0.10240.16545";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Ntoskrnl.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
