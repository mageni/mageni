# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818162");
  script_version("2021-07-15T09:57:41+0000");
  script_cve_id("CVE-2021-34527");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-15 09:57:41 +0000 (Thu, 15 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-09 11:39:50 +0530 (Fri, 09 Jul 2021)");
  script_name("Microsoft Windows Print Spooler RCE Vulnerability (KB5005010)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5005010");

  script_tag(name:"vuldetect", value:"Check if a vulnerable configuration
  is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to microsoft windows
  Print Spooler service fails to restrict access to functionality that
  allows users to add printers and related drivers.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  execute arbitrary code with SYSTEM privileges on a vulnerable system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates.
  In addition to installing the updates users are recommended to either disable
  the Print Spooler service, or to Disable inbound remote printing through
  Group Policy. Please see the references for more information.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5005010");
  script_xref(name:"URL", value:"https://msrc-blog.microsoft.com/2021/07/08/clarified-guidance-for-cve-2021-34527-windows-print-spooler-vulnerability/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1,win2012:1, win2012R2:1,
                   win10:1, win10x64:1, win2016:1, win2008:3, win2019:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath) {
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"spoolsv.exe");
dllVer = fetch_file_version(sysPath:sysPath, file_name:"win32spl.dll");
if(!exeVer && !dllVer) {
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.23381"))
  {
    report = report_fixed_ver(installed_version:dllVer, fixed_version: "6.2.9200.23381");
    security_message(data:report);
    exit(0);
  }
}
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.3.9600.20046")){
    fix = "6.3.9600.20046";
  }
}
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7601.25633")){
    fix = "6.1.7601.25633";
  }
}
else if(hotfix_check_sp(win2008:3) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.0.6003.21138")){
    fix = "6.0.6003.21138";
  }
}
else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_in_range(version:exeVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.4469")){
    fix = "10.0.14393.4470";
  }
  else if(version_in_range(version:exeVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.18968")){
    fix = "10.0.10240.18969";
  }
  else if(version_in_range(version:exeVer, test_version:"10.0.19041.0", test_version2:"10.0.19041.1082")){
    fix = "10.0.19041.1083";
  }
  else if(version_in_range(version:exeVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.1645")){
    fix = "10.0.18362.1646";
  }
  else if(version_in_range(version:exeVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.2028")){
    fix = "10.0.17763.2029";
  }
}

key = "SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
if(registry_key_exists(key:key))
{
  value1 = registry_get_dword(key:key, item:"NoWarningNoElevationOnInstall");
  value2 = registry_get_dword(key:key, item:"UpdatePromptSettings");
}

if(fix)
{
  report = report_fixed_ver(installed_version:exeVer, fixed_version: fix);
  security_message(data:report);
  exit(0);
}
else
{
  if(value1 || value2 && (value1 == "1" || value2 == "1"))
  {
    fix = "Apply workaround given in microsoft advisory to address PrintNightmare";
    report = report_fixed_ver(installed_version:exeVer, fixed_version: fix);
    security_message(data:report);
    exit(0);
  }
}

exit(0);
