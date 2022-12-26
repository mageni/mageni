# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.826815");
  script_version("2022-12-15T10:11:09+0000");
  script_cve_id("CVE-2022-44695");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 10:01:03 +0530 (Wed, 14 Dec 2022)");
  script_name("Microsoft Visio 2013 SP1 Security Feature Bypass Vulnerability (KB5002280");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002280");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a Remote Code
  Execution Vulnerability in Microsoft Visio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Visio 2013 SP1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002280");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}
include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
if(!sysPath){
  exit(0);
}

excelVer = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(!excelVer){
  exit(0);
}

if(version_in_range(version:excelVer, test_version:"15.0", test_version2:"15.0.5481.0999"))
{
  report = report_fixed_ver(file_checked:"visio.exe",
           file_version:excelVer, vulnerable_range:"15.0 - 15.0.5481.0999");
  security_message(data:report);
  exit(0);
}
exit(0);
