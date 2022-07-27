###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Graphics Component Multiple Vulnerabilities (3156754)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807691");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0168", "CVE-2016-0169", "CVE-2016-0170", "CVE-2016-0184",
                "CVE-2016-0195");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-05-11 08:48:17 +0530 (Wed, 11 May 2016)");
  script_name("Microsoft Graphics Component Multiple Vulnerabilities (3156754)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-055.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows Imaging Component fails to properly handle objects in the memory.

  - Windows GDI component fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, and  install
  programs view, change, or delete data, or create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 8.1 x32/x64 Edition

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3156013");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3156016");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3156019");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-055");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Gdi32.dll");
dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Windowscodecs.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\D3d10level9.dll");
dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\Gdi32.dll");

if(dllVer3){
  GdiPath64 = sysPath + "\SysWOW64\Gdi32.dll";
}

if(!dllVer && !dllVer1 && !dllVer2 && !dllVer3){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer)
  {
    ## Presently GDR information is not available.
    if(version_is_less(version:dllVer, test_version:"6.1.7601.23418"))
    {
      Vulnerable_range = "Less than 6.1.7601.23418";
      VULN = TRUE ;
    }
  }

  else if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.1.7601.23418"))
    {
      Vulnerable_range1 = "Less than 6.1.7601.23418";
      VULN1 = TRUE ;
    }
  }

  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.1.7601.23432"))
    {
      Vulnerable_range2 = "Less than 6.1.7601.23432";
      VULN2 = TRUE ;
    }
  }
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.19636"))
    {
      Vulnerable_range = "Less than 6.0.6002.19636";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23949"))
    {
      Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23949";
      VULN = TRUE ;
    }
  }

  else if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"7.0.6002.19636"))
    {
      Vulnerable_range1 = "Less than 7.0.6002.19636";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer1, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23949"))
    {
      Vulnerable_range1 = "7.0.6002.23000 - 7.0.6002.23949";
      VULN1 = TRUE ;
    }
  }

  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"7.0.6002.19647"))
    {
      Vulnerable_range2 = "Less than 7.0.6002.19647";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23949"))
    {
      Vulnerable_range2 = "7.0.6002.23000 - 7.0.6002.23949";
      VULN2 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:dllVer3, test_version:"6.2.9200.21831"))
  {
     report = 'File checked:     ' + GdiPath64 + '\n' +
              'File version:     ' + dllVer3  + '\n' +
              'Vulnerable range:  Less than 6.2.9200.21831\n' ;
     security_message(data:report);
     exit(0);
  }

  else if(version_is_less(version:dllVer1, test_version:"6.2.9200.21831"))
  {
     Vulnerable_range1 =  "Less than 6.2.9200.21831";
     VULN1 = TRUE;
  }

  else if(version_is_less(version:dllVer2, test_version:"6.2.9200.21830"))
  {
     Vulnerable_range2 = "Less than 6.2.9200.21830";
     VULN2 = TRUE;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18302"))
  {
    Vulnerable_range = "Less than 6.3.9600.18302";
    VULN = TRUE ;
  }

  else if(version_is_less(version:dllVer1, test_version:"6.3.9600.18302"))
  {
    Vulnerable_range1 = "Less than 6.3.9600.18302";
    VULN1 = TRUE ;
  }

  else if(version_is_less(version:dllVer2, test_version:"6.3.9600.18302"))
  {
    Vulnerable_range2 = "Less than 6.3.9600.18302";
    VULN2 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16841") )
  {
    Vulnerable_range = "Less than 10.0.10240.16841";
    VULN = TRUE;
  }

  else if(version_in_range(version:dllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.305"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.305";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Gdi32.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Windowscodecs.dll" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\D3d10level9.dll" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
