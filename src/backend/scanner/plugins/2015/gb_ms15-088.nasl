###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Command Line Parameter Information Disclosure Vulnerability (3082458)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806012");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-2423");
  script_bugtraq_id(76202);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-08-12 08:30:53 +0530 (Wed, 12 Aug 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Windows Command Line Parameter Information Disclosure Vulnerability (3082458)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-088.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper security
  restrictions on files stored on an affected system.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to obtain sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows 10 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows Server 2012R2
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3046017");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3079757");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-088");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8:1, win8x64:1, win8_1:1, win8_1x64:1, win2012:1,
                   win2012R2:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Notepad.exe");

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Shell32.dll");

if(!exeVer && !dllVer){
 exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6002.19438"))
    {
      Vulnerable_range = "Less than 6.0.6002.19438";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23745"))
    {
      Vulnerable_range = "6.0.6002.23000" - "6.0.6002.23745";
      VULN1 = TRUE ;
    }
  }
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.19440"))
    {
      Vulnerable_range = "Less than 6.0.6002.19440";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23747"))
    {
      Vulnerable_range = "6.0.6002.23000" - "6.0.6002.23747";
      VULN2 = TRUE ;
    }
  }
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"6.1.7601.18917"))
    {
      Vulnerable_range = "Less than 6.1.7601.18917";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23119"))
    {
      Vulnerable_range = "6.1.7601.22000" - "6.1.7601.23119";
      VULN1 = TRUE ;
    }
  }
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"6.1.7601.18918"))
    {
      Vulnerable_range = "Less than 6.1.7601.18918";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23120"))
    {
      Vulnerable_range = "6.1.7601.22000" - "6.1.7601.23120";
      VULN2 = TRUE ;
    }
  }
}

## Win 8 and 2012
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0 && exeVer)
{
  if(version_is_less(version:exeVer, test_version:"6.2.9200.17434"))
  {
    Vulnerable_range = "Less than 6.2.9200.17434";
    VULN1 = TRUE ;
  }
  else if(version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21544"))
  {
    Vulnerable_range = "6.2.9200.20000" - "6.2.9200.21544";
    VULN1 = TRUE ;
  }
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && exeVer)
{
  if(version_is_less(version:exeVer, test_version:"6.3.9600.17930"))
  {
    Vulnerable_range = "Less than 6.3.9600.17930";
    VULN1 = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0 && exeVer)
{
  if(version_is_less(version:exeVer, test_version:"10.0.10240.16425"))
  {
    Vulnerable_range = "Less than 10.0.10240.16425";
    VULN1 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\system32\Notepad.exe" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\Shell32.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
