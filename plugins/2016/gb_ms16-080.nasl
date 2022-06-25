###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows PDF Library Multiple Vulnerabilities (3164302)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808226");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3201", "CVE-2016-3203", "CVE-2016-3215");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-15 08:30:23 +0530 (Wed, 15 Jun 2016)");
  script_name("Microsoft Windows PDF Library Multiple Vulnerabilities (3164302)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-080");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An information disclosure vulnerabilities exist in Microsoft Windows when
    a user opens a specially crafted .pdf file.

  - The remote code execution vulnerability exists in Microsoft Windows when
    a specially crafted file is opened in Windows Reader.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to cause arbitrary code to execute in the context of the
  current user, and also could gain the same user rights as the current user
  and to trick the user into opening the .pdf file and read information in the
  context of the current user.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3164302");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-080");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-080");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Glcndfilter.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\Windows.data.pdf.dll");
if(!dllVer1 && !dllVer2){
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"6.2.9200.21860"))
  {
     Vulnerable_range = "Less than 6.2.9200.21860";
     VULN1 = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"6.3.9600.18336"))
  {
    Vulnerable_range = "Less than 6.3.9600.18336";
    VULN2 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer2)
{
  if(version_is_less(version:dllVer2, test_version:"10.0.10240.16942"))
  {
    Vulnerable_range = "Less than 10.0.10240.16942";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:dllVer2, test_version:"10.0.10586.0", test_version2:"10.0.10586.419"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.419";
    VULN2 = TRUE ;
  }
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\system32\windows.data.pdf.dll"+ '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\system32\Glcndfilter.dll" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
