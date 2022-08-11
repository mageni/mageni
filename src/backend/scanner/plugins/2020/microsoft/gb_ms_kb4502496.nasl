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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816565");
  script_version("2020-02-12T15:13:02+0000");
  script_cve_id("CVE-2020-0689");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-12 15:13:02 +0000 (Wed, 12 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-12 09:33:17 +0530 (Wed, 12 Feb 2020)");
  script_name("Microsoft Windows Secure Boot Security Feature Bypass Vulnerability (KB4502496)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4502496");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in secure boot.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  bypass security restriction and run a specially crafted application.");

  script_tag(name:"affected", value:"Windows 10 Version 1507 for 32-bit Systems

  Windows 10 Version 1507 for x64-based Systems

  Windows 8.1 for 32-bit systems

  Windows 8.1 for x64-based systems

  Windows Server 2012

  Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4502496/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win10:1, win10x64:1, win8_1:1, win8_1x64:1, win2012R2:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Tpmtasks.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.10240", test_version2:"10.0.10240.18366")){
    vulnerable_range = "10.0.10240 - 10.0.10240.18366";
  }
}

else if (hotfix_check_sp( win8_1:1, win8_1x64:1, win2012R2:1)  > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.19501")){
    vulnerable_range = "Less than 6.3.9600.19501";
  }
}

else if (hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.22884")){
    vulnerable_range = "Less than 6.2.9200.22884";
  }
}

if(vulnerable_range)
{
  report = report_fixed_ver(file_checked:sysPath + "\Tpmtasks.dll",
                            file_version:dllVer, vulnerable_range:vulnerable_range);
  security_message(data:report);
  exit(0);
}
exit(99);
