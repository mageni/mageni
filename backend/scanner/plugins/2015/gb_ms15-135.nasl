###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Kernel-Mode Drivers Code Execution Vulnerability (3119075)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806776");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6171", "CVE-2015-6173", "CVE-2015-6174", "CVE-2015-6175",
                "CVE-2015-6106", "CVE-2015-6107", "CVE-2015-6108");
  script_bugtraq_id(78509, 78510, 78513, 78514, 78497, 78498, 78499);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-09 08:11:32 +0530 (Wed, 09 Dec 2015)");
  script_name("Microsoft Windows Kernel-Mode Drivers Code Execution Vulnerability (3119075)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-135.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple local privilege-escalation vulnerabilities.

  - Multiple remote code execution vulnerabilities when the Windows font library
    improperly handles specially crafted embedded fonts");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in kernel mode with elevated privileges.");

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

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3119075");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-135");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-128");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\User32.dll");
if(!dllVer){
  exit(0);
}

if (dllVer =~ "^(6\.0\.6002\.1)"){
  Vulnerable_range = "Less than 6.0.6002.19535";
}
else if (dllVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23844";
}
else if (dllVer =~ "^(6\.2\.9200\.1)"){
  Vulnerable_range = "Less than 6.2.9200.17568";
}
else if (dllVer =~ "^(6\.2\.9200\.2)"){
  Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21686";
}
else if (dllVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18123";
}
else if (dllVer =~ "^(6\.1\.7600\.1)"){
  Vulnerable_range = "Less than 6.1.7601.19061";
}
else if (dllVer =~ "^(6\.1\.7601\.1)"){
  Vulnerable_range = "Less than 6.1.7601.19061";
}
else if (dllVer =~ "^(6\.1\.7601\.2)"){
  Vulnerable_range = "6.1.7601.22000 - 6.1.7601.23264";
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19535")||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23844")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.19061") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23264")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17568") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21686")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18123")){
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16384"))
  {
    Vulnerable_range = "Less than 10.0.10240.16384";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.19"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\User32.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
