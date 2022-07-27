###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Uniscribe Multiple Vulnerabilities (4013076)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810812");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0072", "CVE-2017-0083", "CVE-2017-0084", "CVE-2017-0085",
		"CVE-2017-0086", "CVE-2017-0087", "CVE-2017-0088", "CVE-2017-0089",
		"CVE-2017-0090", "CVE-2017-0091", "CVE-2017-0092", "CVE-2017-0111",
		"CVE-2017-0112", "CVE-2017-0113", "CVE-2017-0114", "CVE-2017-0115",
		"CVE-2017-0116", "CVE-2017-0117", "CVE-2017-0118", "CVE-2017-0119",
		"CVE-2017-0120", "CVE-2017-0121", "CVE-2017-0122", "CVE-2017-0123",
		"CVE-2017-0124", "CVE-2017-0125", "CVE-2017-0126", "CVE-2017-0127",
		"CVE-2017-0128");
  script_bugtraq_id(96599, 96608, 96610, 96652, 96603, 96604, 96605, 96606, 96607,
		    96657, 96676, 96658, 96659, 96660, 96661, 96663, 96665, 96679,
		    96680, 96666, 96667, 96678, 96668, 96669, 96670, 96672, 96673,
		    96674, 96675);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-15 10:00:42 +0530 (Wed, 15 Mar 2017)");
  script_name("Microsoft Uniscribe Multiple Vulnerabilities (4013076)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-011.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The way Windows Uniscribe handles objects in memory.

  - When Windows Uniscribe improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system, also to obtain information to further
  compromise the user's system.");

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-011");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, winVistax64:3,
                   win2008x64:3, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

usrVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Usp10.dll");
mshVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Mshtml.dll");
icmVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Icm32.dll");

if(!usrVer && !mshVer && !icmVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && usrVer)
{
    if(version_is_less(version:usrVer, test_version:"1.626.7601.23688"))
    {
      Vulnerable_range1 = "Less than 1.626.7601.23688";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0 && usrVer)
{
    if(version_is_less(version:usrVer, test_version:"1.626.6002.19743"))
    {
      Vulnerable_range1 = "Less than 1.626.6002.19743";
      VULN1 = TRUE ;
    }

    else if(version_in_range(version:usrVer, test_version:"1.626.6002.24000", test_version2:"1.626.6002.24066"))
    {
      Vulnerable_range1 = "1.626.6002.24000 - 1.626.6002.24066";
      VULN1 = TRUE ;
    }
}

else if(hotfix_check_sp(win2012:1) > 0 && mshVer)
{
  if(version_is_less(version:mshVer, test_version:"10.0.9200.22104"))
  {
     Vulnerable_range = "Less than 10.0.9200.22104";
     VULN = TRUE ;
  }

  else if(version_is_less(version:icmVer, test_version:"6.2.9200.22086"))
  {
     Vulnerable_range2 = "Less than 6.2.9200.22086";
     VULN2 = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:icmVer, test_version:"6.3.9600.18589"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Icm32.dll" + '\n' +
             'File version:     ' + icmVer  + '\n' +
             'Vulnerable range:  Less than 6.3.9600.18589\n' ;
    security_message(data:report);
    exit(0);
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && mshVer)
{
  if(version_is_less(version:mshVer, test_version:"11.0.10240.17319") )
  {
    Vulnerable_range = "Less than 11.0.10240.17319";
    VULN = TRUE;
  }

  else if(version_in_range(version:mshVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.838"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.838";
    VULN = TRUE ;
  }

  else if(version_in_range(version:mshVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.952"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
    VULN = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Usp10.dll" + '\n' +
           'File version:     ' + usrVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Mshtml.dll" + '\n' +
           'File version:     ' + mshVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\icm32.dll" + '\n' +
           'File version:     ' + icmVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
