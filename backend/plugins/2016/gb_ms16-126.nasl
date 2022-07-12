###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Messaging API Information Disclosure Vulnerability (3196067)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809345");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3298");
  script_bugtraq_id(93392);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-10-12 08:11:15 +0530 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Messaging API Information Disclosure Vulnerability (3196067)");

  script_tag(name:"summary", value:"This host is missing a moderate security
  update according to Microsoft Bulletin MS16-126.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure vulnerability exists
  when the Microsoft Internet Messaging API improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  test for the presence of files on disk.");

  script_tag(name:"affected", value:"Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3196067");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-126");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-126");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

Win32Ver = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
oleVer = fetch_file_version(sysPath:sysPath, file_name:"inetcomm.dll");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!Win32Ver && !oleVer && !edgeVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && Win32Ver)
{
  if(version_is_less(version:Win32Ver, test_version:"6.1.7601.23545"))
  {
    Vulnerable_range = "Less than 6.1.7601.23545";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0 && oleVer)
{
  if(version_is_less(version:oleVer, test_version:"6.0.6002.19694"))
  {
    Vulnerable_range1 = "Less than 6.0.6002.19694";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:oleVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24017"))
  {
    Vulnerable_range1 = "6.0.6002.23000 - 6.0.6002.24017";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && Win32Ver)
{
  if(version_is_less(version:Win32Ver, test_version:"6.2.9200.21977"))
  {
    Vulnerable_range = "Less than 6.2.9200.21977";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012R2:1, win8_1:1, win8_1x64:1) > 0 && Win32Ver)
{
  if(version_is_less(version:Win32Ver, test_version:"6.3.9600.18470"))
  {
    Vulnerable_range = "Less than 6.3.9600.18470";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17146"))
  {
    Vulnerable_range2 = "Less than 11.0.10240.17146";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
  {
    Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.632";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.320";
    VULN2 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + Win32Ver  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\inetcomm.dll" + '\n' +
           'File version:     ' + oleVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
