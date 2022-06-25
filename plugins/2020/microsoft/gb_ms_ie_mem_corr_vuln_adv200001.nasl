# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816614");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2020-0674");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 13:36:02 +0530 (Mon, 27 Jan 2020)");
  script_name("Microsoft Internet Explorer Scripting Engine Memory Corruption Vulnerability (ADV200001)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft advisory ADV200001.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the way that the scripting
  engine handles objects in memory in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user. An attacker who
  successfully exploited the vulnerabilities could gain the same user rights as the
  current user and execute arbitrary code.");

  script_tag(name:"affected", value:"Internet Explorer 9, 10 and 11");

  script_tag(name:"solution", value:"As a workaround restrict access to JScript.dll.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4534251");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");


if(hotfix_check_sp(win2008:3, win2008x64:3, win2012:1, win7:2, win7x64:2,
                   win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^(9|1[01])\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Jscript.dll");
dllVer = fetch_file_version(sysPath:iePath, file_name:"User32.dll");
dllVer1 = fetch_file_version(sysPath:iePath, file_name:"Gdiplus.dll");
if(!iedllVer || !dllVer || !dllVer1){
  exit(0);
}

if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
  if(ieVer =~ "^9\." && version_is_less_equal(version:iedllVer, test_version:"5.8.7601.21387")){
    Vulnerable_range1 = "Less than 5.8.7601.21387";
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(ieVer =~ "^11\." && version_is_less_equal(version:iedllVer, test_version:"5.8.9600.19597")){
    Vulnerable_range1 = "Less than 5.8.9600.19597";
  }

  else if(ieVer =~ "^10\." && version_is_less_equal(version:iedllVer, test_version:"5.8.9200.22949")){
    Vulnerable_range1 = "Less than 5.8.9200.22949";
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(ieVer =~ "^11\." && version_is_less_equal(version:iedllVer, test_version:"5.8.9600.19597")){
    Vulnerable_range1 = "Less than 5.8.9600.19597";
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && ieVer =~ "^11\.")
{
  if(version_in_range(version:dllVer, test_version:"10.0.17134.0", test_version2:"10.0.17134.1246")){
    Vulnerable_range2 = "10.0.17134.0 - 10.0.17134.1246";
  }
  else if(version_in_range(version:dllVer1, test_version:"10.0.17763.0", test_version2:"10.0.17763.973")){
    Vulnerable_range3 = "10.0.17763.0 - 10.0.17763.973";
  }
  else if(version_in_range(version:dllVer1, test_version:"10.0.18362.0", test_version2:"10.0.18362.592")){
    Vulnerable_range3 = "10.0.18362.0 - 10.0.18362.592";
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.16299.0", test_version2:"10.0.16299.1625")){
    Vulnerable_range2 = "10.0.16299.0 - 10.0.16299.1625";
  }
  else if(version_in_range(version:dllVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.18453")){
    Vulnerable_range2 = "10.0.10240.0 - 10.0.10240.18453";
  }
  else if(version_in_range(version:dllVer1, test_version:"10.0.14393.0", test_version2:"10.0.14393.3442")){
    Vulnerable_range3 = "10.0.14393.0 - 10.0.14393.3442";
  }

}

if(Vulnerable_range1)
{
  report = report_fixed_ver(file_checked:iePath + "\Jscript.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range1);
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range2)
{
  report = report_fixed_ver(file_checked:iePath + "\User32.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range2);
  security_message(data:report);
  exit(0);
}

if(Vulnerable_range3)
{
  report = report_fixed_ver(file_checked:iePath + "\Gdiplus.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range3);
  security_message(data:report);
  exit(0);
}

exit(0);
