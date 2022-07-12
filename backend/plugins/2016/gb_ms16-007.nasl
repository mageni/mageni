###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (3124901)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807029");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0014", "CVE-2016-0015", "CVE-2016-0016", "CVE-2016-0018",
                "CVE-2016-0019", "CVE-2016-0020");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-01-13 09:01:03 +0530 (Wed, 13 Jan 2016)");
  script_name("Microsoft Windows Multiple Vulnerabilities (3124901)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-007.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A security feature bypass vulnerability exists in Windows Remote Desktop
    Protocol, that is caused when Windows hosts running RDP services fail to
    prevent remote logon to accounts that have no passwords set.

  - Multiple elevation of privilege vulnerabilities exist when Windows
    improperly validates input before loading dynamic link library (DLL) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to the remote host as another user, possibly with elevated
  privileges and to take complete control of an affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 10 x32/x64

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3121918");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3109560");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3110329");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3108664");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-007");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Advapi32.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\Qedit.dll");
dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"System32\Devenum.dll");
dllVer4 = fetch_file_version(sysPath:sysPath, file_name:"System32\Mapi32.dll");
dllVer5 = fetch_file_version(sysPath:sysPath, file_name:"System32\Aeinv.dll");

dllVer6 = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\Advapi32.dll");
if(dllVer6){
  adPath64 = sysPath + "\SysWOW64\Advapi32.dll";
}

if(!dllVer1 && !dllVer2 && !dllVer3 && !dllVer4 && !dllVer5 && !dllVer6){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.1.7601.19091"))
    {
      Vulnerable_range1 = "Less than 6.1.7601.19091";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer1, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23289"))
    {
      Vulnerable_range1 = "6.1.7601.23000 - 6.1.7601.23289";
      VULN1 = TRUE ;
    }
  }
  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"6.6.7601.19091"))
    {
      Vulnerable_range3 = "Less than 6.6.7601.19091";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"6.6.7601.23000", test_version2:"6.6.7601.23289"))
    {
      Vulnerable_range3 = "6.6.7601.23000 - 6.6.7601.23289";
      VULN3 = TRUE ;
    }
  }

  if(dllVer4 && version_is_less(version:dllVer4, test_version:"1.0.2536.0"))
  {
    Vulnerable_range4 = "Less than 1.0.2536.0";
    VULN4 = TRUE ;
  }

  ## Aeinv.dll is not for win2008r2
  if(hotfix_check_sp(win7:2, win7x64:2) > 0 && dllVer5)
  {
    if(version_in_range(version:dllVer5, test_version:"10.0", test_version2:"10.0.11065.0999"))
    {
      Vulnerable_range5 = "10.0 - 10.0.11065.0999";
      VULN5 = TRUE ;
    }
  }
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.0.6002.19555"))
    {
      Vulnerable_range1 = "Less than 6.0.6002.19555";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer1, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23864"))
    {
      Vulnerable_range1 = "6.0.6002.23000 - 6.0.6002.23864";
      VULN1 = TRUE ;
    }
  }

  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.6.6002.19554"))
    {
      Vulnerable_range2 = "Less than 6.6.6002.19554";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.6.6002.23000", test_version2:"6.6.6002.23863"))
    {
      Vulnerable_range2 = "6.6.6002.23000 - 6.6.6002.23863";
      VULN2 = TRUE ;
    }
  }

  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"6.6.6002.19554"))
    {
      Vulnerable_range3 = "Less than 6.6.6002.19554";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"6.6.6002.23000", test_version2:"6.6.6002.23863"))
    {
      Vulnerable_range3 = "6.6.6002.23000 - 6.6.6002.23863";
      VULN3 = TRUE ;
    }
  }
  if(dllVer4 && version_is_less(version:dllVer4, test_version:"1.0.2536.0"))
  {
    Vulnerable_range4 = "Less than 1.0.2536.0";
    VULN4 = TRUE ;
  }
}

## Win 8
else if(hotfix_check_sp(win8:1, win8x64:1) > 0)
{
  if(hotfix_check_sp(win8:1) > 0 && dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.2.9200.17592"))
    {
      Vulnerable_range1 = "Less than 6.2.9200.17592";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer1, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21712"))
    {
      Vulnerable_range1 = "6.2.9200.21000 - 6.2.9200.21712";
      VULN1 = TRUE ;
    }
  }
  else if(hotfix_check_sp(win8x64:1) > 0 && dllVer6)
  {
    if(version_is_less(version:dllVer6, test_version:"6.2.9200.17591"))
    {
      report = 'File checked:     ' + adPath64 + '\n' +
               'File version:     ' + dllVer6  + '\n' +
               'Vulnerable range:  Less than 6.2.9200.17591\n' ;
      security_message(data:report);
      exit(0);
    }
    else if(version_in_range(version:dllVer6, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21713"))
    {
      report = 'File checked:     ' + adPath64 + '\n' +
               'File version:     ' + dllVer6  + '\n' +
               'Vulnerable range: 6.2.9200.21000 - 6.2.9200.21713\n' ;
      security_message(data:report);
      exit(0);
    }
  }

  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.6.9200.17590"))
    {
      Vulnerable_range2 = "Less than 6.6.9200.17590";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.6.9200.21000", test_version2:"6.6.9200.21707"))
    {
      Vulnerable_range2 = "6.6.9200.21000 - 6.6.9200.21707";
      VULN2 = TRUE ;
    }
  }

  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"6.6.9200.17590"))
    {
      Vulnerable_range3 = "Less than 6.6.9200.17590";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"6.6.9200.21000", test_version2:"6.6.9200.21707"))
    {
      Vulnerable_range3 = "6.6.9200.21000 - 6.6.9200.21707";
      VULN3 = TRUE ;
    }
  }
  if(dllVer5 && version_in_range(version:dllVer5, test_version:"10.0", test_version2:"10.0.11065.0999"))
  {
    Vulnerable_range5 = "10.0 - 10.0.11065.0999";
    VULN5 = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(dllVer6)
  {
    if(version_is_less(version:dllVer6, test_version:"6.2.9200.17591"))
    {
      report = 'File checked:     ' + adPath64 + '\n' +
               'File version:     ' + dllVer6  + '\n' +
               'Vulnerable range:  Less than 6.2.9200.17591\n' ;
      security_message(data:report);
      exit(0);
    }
    else if(version_in_range(version:dllVer6, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21713"))
    {
      report = 'File checked:     ' + adPath64 + '\n' +
               'File version:     ' + dllVer6  + '\n' +
               'Vulnerable range:  6.2.9200.21000 - 6.2.9200.21713\n' ;
      security_message(data:report);
      exit(0);
    }
  }

  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.6.9200.17590"))
    {
      Vulnerable_range2 = "Less than 6.6.9200.17590";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.6.9200.21000", test_version2:"6.6.9200.21707"))
    {
      Vulnerable_range2 = "6.6.9200.21000 - 6.6.9200.21707";
      VULN2 = TRUE ;
    }
  }

  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"6.6.9200.17590"))
    {
      Vulnerable_range3 = "Less than 6.6.9200.17590";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"6.6.9200.21000", test_version2:"6.6.9200.21707"))
    {
      Vulnerable_range3 = "6.6.9200.21000 - 6.6.9200.21707";
      VULN3 = TRUE ;
    }
  }
}


## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(dllVer1 && version_is_less(version:dllVer1, test_version:"6.3.9600.18155"))
  {
    Vulnerable_range1 = "Less than 6.3.9600.18155";
    VULN1 = TRUE ;
  }
  if(dllVer2 && version_is_less(version:dllVer2, test_version:"6.6.9600.18152"))
  {
    Vulnerable_range2 = "Less than 6.6.9600.18152";
    VULN2 = TRUE ;
  }
  if(dllVer3 && version_is_less(version:dllVer3, test_version:"6.6.9600.18154"))
  {
    Vulnerable_range3 = "Less than 6.6.9600.18154";
    VULN3 = TRUE ;
  }
  if(dllVer5 && version_in_range(version:dllVer5, test_version:"10.0", test_version2:"10.0.11065.0999"))
  {
    Vulnerable_range5 = "10.0 - 10.0.11065.0999";
    VULN5 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"10.0.10240.16644"))
  {
    Vulnerable_range2 = "Less than 10.0.10240.16644";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:dllVer2, test_version:"10.0.10586.0", test_version2:"10.0.10586.62"))
  {
    Vulnerable_range2 = "10.0.10586.0 - 10.0.10586.62";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Advapi32.dl" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\Qedit.dll" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\System32\Devenum.dll" + '\n' +
           'File version:     ' + dllVer3  + '\n' +
           'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN4)
{
  report = 'File checked:     ' + sysPath + "\System32\Mapi32.dll" + '\n' +
           'File version:     ' + dllVer4  + '\n' +
           'Vulnerable range: ' + Vulnerable_range4 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN5)
{
  report = 'File checked:     ' + sysPath + "\System32\Aeinv.dll" + '\n' +
           'File version:     ' + dllVer5  + '\n' +
           'Vulnerable range: ' + Vulnerable_range5 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
