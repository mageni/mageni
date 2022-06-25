###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Graphics Component Multiple Vulnerabilities (3199120)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809466");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-7210", "CVE-2016-7205", "CVE-2016-7217", "CVE-2016-7256");
  script_bugtraq_id(94030, 94033, 94066, 94156);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-09 09:56:10 +0530 (Wed, 09 Nov 2016)");
  script_name("Microsoft Graphics Component Multiple Vulnerabilities (3199120)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-132.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - the ATMFD component improperly discloses the contents of its memory.

  - the Windows Animation Manager improperly handles objects in memory.

  - the Windows font library improperly handles specially crafted embedded fonts.

  - the Windows Media Foundation improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to install programs, view, change, or delete data, or create new accounts with
  full user rights, and to obtain information to further compromise the user's
  system.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows 10 x32/x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3199120");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-132");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllver = fetch_file_version(sysPath:sysPath, file_name:"fontsub.dll");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!dllver && !edgeVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.1.7601.23587"))
  {
    Vulnerable_range = "Less than 6.1.7601.23587";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.0.6002.18272"))
  {
    Vulnerable_range = "Less than 6.0.6002.18272";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllver, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24031"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24031";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.3.9600.17415"))
  {
    Vulnerable_range = "Less than 6.3.9600.17415";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.2.9200.16384"))
  {
    Vulnerable_range = "Less than 6.2.9200.16384";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17184"))
  {
    Vulnerable_range2 = "Less than 11.0.10240.17184";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.671"))
  {
    Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.671";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.446"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.446";
    VULN2 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\fontsub.dll" + '\n' +
           'File version:     ' + dllver  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
