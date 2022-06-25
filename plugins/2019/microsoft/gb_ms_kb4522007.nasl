# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815621");
  script_version("2019-09-25T12:48:23+0000");
  script_cve_id("CVE-2019-1367");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-25 12:48:23 +0000 (Wed, 25 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-24 11:20:47 +0530 (Tue, 24 Sep 2019)");
  script_name("Microsoft Windows Scripting Engine Memory Corruption Vulnerability (KB4522007)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4522007");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exist due to an error in the way
  that the scripting engine handles objects in memory in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Internet Explorer 9 on Windows Server 2008 x32/x64

  Internet Explorer 10 on Windows Server 2012

  Internet Explorer 11 on Windows 7 x32/x64,

  Windows 8.1 x32/x64,

  Windows Server 2008 R2 x64,

  Windows Server 2012 and Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4522007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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
include("host_details.inc");

if(hotfix_check_sp(win2008:3, win2008x64:3, win2012:1, win7:2, win7x64:2,
                   win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
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

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21372")){
    Vulnerable_range = "Less than 9.0.8112.21372";
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.22880")){
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.22880";
  }

  else if(version_in_range(version:iedllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.19466")){
    Vulnerable_range = "11.0.9600.00000 - 11.0.9600.19466";
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.19466")){
    Vulnerable_range = "11.0.9600.00000 - 11.0.9600.19466";
  }
}

if(Vulnerable_range)
{
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range);
  security_message(data:report);
}
exit(0);
