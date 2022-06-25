###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Information Disclosure And Elevation of Privilege Vulnerabilities (3205655)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810238");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-7219", "CVE-2016-7292");
  script_bugtraq_id(94768, 94764);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-12-14 08:20:30 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Information Disclosure And Elevation of Privilege Vulnerabilities (3205655)");

  script_tag(name:"summary", value:"This host is missing an critical security
  update according to Microsoft Bulletin MS16-149.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to

  - The windows Crypto driver running in kernel mode improperly handles objects
    in memory.

  - The windows Installer fails to properly sanitize input leading to an insecure
    library loading behavior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain information to further compromise the user's system, run arbitrary
  code with elevated system privileges. An attacker could then install programs,
  view, change, or delete data or create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2016
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows 10 Version 1607 x32/x64
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3205655");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-149");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-149");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

msiVer = fetch_file_version(sysPath:sysPath, file_name:"system32\msi.dll");
lsVer = fetch_file_version(sysPath:sysPath, file_name:"system32\lsasrv.dll");
if(!msiVer && !lsVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:msiVer, test_version:"4.5.6002.19712") && msiVer)
  {
    Vulnerable_range1 = "Less than 4.5.6002.19712";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:msiVer, test_version:"4.5.6002.23000", test_version2:"4.5.6002.24033") && msiVer)
  {
    Vulnerable_range1 = "4.5.6002.23000" - "4.5.6002.24033";
    VULN1 = TRUE ;
  }

  if(version_is_less(version:lsVer, test_version:"6.0.6002.19701") && lsVer)
  {
    Vulnerable_range2 = "Less than 6.0.6002.19701";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:lsVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24042") && lsVer)
  {
    Vulnerable_range2 = "6.0.6002.23000" - "6.0.6002.24042";
    VULN2 = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && msiVer)
{
  if(version_is_less(version:msiVer, test_version:"5.0.7601.23593"))
  {
    Vulnerable_range1 = "Less than 5.0.7601.23593";
    VULN1 = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && msiVer)
{
  if(version_is_less(version:msiVer, test_version:"5.0.9600.18533"))
  {
    Vulnerable_range1 = "Less than 5.0.9600.18533";
    VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && msiVer)
{
  if(version_is_less(version:msiVer, test_version:"5.0.9200.22028"))
  {
     Vulnerable_range1 = "Less than 5.0.9200.17412";
     VULN1 = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && msiVer)
{
  if(version_is_less(version:msiVer, test_version:"5.0.10240.17202"))
  {
    Vulnerable_range1 = "Less than 5.0.10240.17202";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:msiVer, test_version:"5.0.10586.0", test_version2:"5.0.10586.712"))
  {
    Vulnerable_range1 = "5.0.10586.0 - 5.0.10586.712";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:msiVer, test_version:"5.0.14393.0", test_version2:"5.0.14393.575"))
  {
    Vulnerable_range1 = "5.0.14393.0 - 5.0.14393.575";
    VULN1 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\msi.dll" + '\n' +
           'File version:     ' + msiVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\lsasrv.dll" + '\n' +
           'File version:     ' + lsVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
