###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (3134228)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807065");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0040", "CVE-2016-0041", "CVE-2016-0042", "CVE-2016-0044",
                "CVE-2016-0049");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-02-10 14:13:40 +0530 (Wed, 10 Feb 2016)");
  script_name("Microsoft Windows Multiple Vulnerabilities (3134228)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-014.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Windows kernel improperly handles objects in memory.

  - Windows improperly validates input before loading dynamic link library
    (DLL) files.

  - Insufficient validation of input by Microsoft Sync Framework.

  - Kerberos fails to check the password change of a user signing into a
    workstation.

  - A security feature bypass vulnerability exists in Windows Remote Desktop
    Protocol, that is caused when Windows hosts running RDP services fail to
    prevent remote logon to accounts that have no passwords set.

  - Multiple elevation of privilege vulnerabilities exist when Windows
    improperly validates input before loading dynamic link library (DLL) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in kernel mode, to cause denial of service
  conditions, to bypass authentication and can launch further attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 10 x32/x64

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

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3126587");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3126593");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3126434");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3135174");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-014");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,  win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Winsync.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\Ntdll.dll");
dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"System32\Mtxoci.dll");
dllVer4 = fetch_file_version(sysPath:sysPath, file_name:"System32\Msorcl32.dll");

if(!dllVer1 && !dllVer2 && !dllVer3 && !dllVer4){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.1.7601.19117"))
    {
      Vulnerable_range2 = "Less than 6.1.7601.19117";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23320"))
    {
      Vulnerable_range2 = "6.1.7601.23000 - 6.1.7601.23320";
      VULN2 = TRUE ;
    }
  }
  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"2001.12.8531.19135"))
    {
      Vulnerable_range3 = "2001.12.8531.19135";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"2001.12.8531.23000", test_version2:"2001.12.8531.23337"))
    {
      Vulnerable_range3 = "2001.12.8531.23000 - 2001.12.8531.23337";
      VULN3 = TRUE ;
    }
  }
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.0.6002.19580"))
    {
      Vulnerable_range2 = "Less than 6.0.6002.19580";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23889"))
    {
      Vulnerable_range2 = "6.0.6002.23000 - 6.0.6002.23889";
      VULN2 = TRUE ;
    }
  }
  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"2001.12.6932.19580"))
    {
      Vulnerable_range3 = "Less than 2001.12.6932.19580";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"2001.12.6932.23890", test_version2:"2001.12.6932.23889"))
    {
      Vulnerable_range3 = "2001.12.6932.23890 - 2001.12.6932.23889";
      VULN3 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.2.9200.17623"))
    {
      Vulnerable_range2 = "Less than 6.2.9200.17623";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21742"))
    {
      Vulnerable_range2 = "6.2.9200.21000 - 6.2.9200.21742";
      VULN2 = TRUE ;
    }
  }
  if(dllVer3)
  {
    if(version_is_less(version:dllVer3, test_version:"2001.12.10130.17623"))
    {
      Vulnerable_range3 = "Less than 2001.12.10130.17623";
      VULN3 = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"2001.12.10130.21000", test_version2:"2001.12.10130.21742"))
    {
      Vulnerable_range3 = "2001.12.10130.21000 - 2001.12.10130.21742";
      VULN3 = TRUE ;
    }
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(dllVer1 && version_is_less(version:dllVer1, test_version:"2007.94.9600.18183"))
  {
    Vulnerable_range1 = "Less than 2007.94.9600.18183";
    VULN1 = TRUE ;
  }
  if(dllVer2 && version_is_less(version:dllVer2, test_version:"6.3.9600.18192"))
  {
    Vulnerable_range2 = "Less than 6.3.9600.18192";
    VULN2 = TRUE ;
  }
  if(dllVer3 && version_is_less(version:dllVer3, test_version:"2001.12.10530.18192"))
  {
    Vulnerable_range3 = "Less than 2001.12.10530.18192";
    VULN3 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer4)
{
  if(version_is_less(version:dllVer4, test_version:"10.0.10240.16683"))
  {
    Vulnerable_range4 = "Less than 10.0.10240.16683";
    VULN4 = TRUE ;
  }
  else if(version_in_range(version:dllVer4, test_version:"10.0.10586.0", test_version2:"10.0.10586.102"))
  {
    Vulnerable_range4 = "10.0.10586.0 - 10.0.10586.102";
    VULN4 = TRUE ;
  }
}


if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Winsync.dll" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\Ntdll.dll" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
}

if(VULN3)
{
  report = 'File checked:     ' + sysPath + "\System32\Mtxoci.dll" + '\n' +
           'File version:     ' + dllVer3  + '\n' +
           'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
  security_message(data:report);
}

if(VULN4)
{
  report = 'File checked:     ' + sysPath + "\System32\Msorcl32.dll" + '\n' +
           'File version:     ' + dllVer4  + '\n' +
           'Vulnerable range: ' + Vulnerable_range4 + '\n' ;
  security_message(data:report);
}

exit(0);
