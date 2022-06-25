###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (3199172)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809465");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-7221", "CVE-2016-7222", "CVE-2016-7212");
  script_bugtraq_id(94021, 94023, 94027);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-09 08:29:26 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Multiple Vulnerabilities (3199172)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-130.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - The Windows Input Method Editor (IME) improperly handles DLL loading.

  - The Windows Task Scheduler improperly schedule a new task.

  - The Windows image file loading functionality does not properly handle
    malformed image files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code with elevated system privileges or run a specially
  crafted application.");

  script_tag(name:"affected", value:"Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3199172");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-130");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-130");

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

sysVer = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
asyVer = fetch_file_version(sysPath:sysPath, file_name:"asycfilt.dll");
ctfdll = fetch_file_version(sysPath:sysPath, file_name:"msctf.dll");
if(!sysVer && !edgeVer && !asyVer && !ctfdll){
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && sysVer)
{
  if(version_is_less(version:sysVer, test_version:"6.3.9600.18524"))
  {
    Vulnerable_range = "Less than 6.3.9600.18524";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && sysVer)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7601.23584"))
  {
    Vulnerable_range = "Less than 6.1.7601.23584";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 )
{
  if(sysVer)
  {
    if(version_is_less(version:sysVer, test_version:"6.2.9200.22023"))
    {
      Vulnerable_range = "Less than 6.2.9200.22023";
      VULN = TRUE ;
    }
  }
  if(ctfdll)
  {
    if(version_is_less(version:ctfdll, test_version:"6.0.6002.19705"))
    {
      Vulnerable_range4 = "Less than 6.0.6002.19705";
      VULN4 = TRUE ;
    }

    else if(version_in_range(version:ctfdll, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24027"))
    {
      Vulnerable_range4 = "6.0.6002.23000 - 6.0.6002.24027";
      VULN4 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0 && asyVer)
{
  if(version_is_less(version:asyVer, test_version:"6.0.6002.19700"))
  {
    Vulnerable_range3 = "Less than 6.0.6002.19700";
    VULN3 = TRUE ;
  }
  else if(version_in_range(version:asyVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24023"))
  {
    Vulnerable_range3 = "6.0.6002.23000 - 6.0.6002.24023";
    VULN3 = TRUE ;
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
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
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

else if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\asycfilt.dll" + '\n' +
           'File version:     ' + asyVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN4)
{
  report = 'File checked:     ' + sysPath + "\msctf.dll" + '\n' +
           'File version:     ' + ctfdll  + '\n' +
           'Vulnerable range: ' + Vulnerable_range4 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);