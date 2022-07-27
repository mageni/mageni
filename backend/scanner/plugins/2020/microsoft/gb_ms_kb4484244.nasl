# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.81688");
  script_version("2020-04-17T06:25:22+0000");
  script_cve_id("CVE-2020-0760");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-17 09:53:31 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 13:01:44 +0530 (Thu, 16 Apr 2020)");
  script_name("Microsoft Visio Remote Code Execution Vulnerability (KB4484244)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4484244");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Visio software
  fails to loads arbitrary type libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system. An attacker could then install programs,
  view, change, or delete data or create new accounts with full user rights.");

  script_tag(name:"affected", value:"- Microsoft Visio 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4484244");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.4993.1000"))
{
  report = report_fixed_ver(file_checked:"visio.exe",
           file_version:excelVer, vulnerable_range:"16.0 - 16.0.4993.1000");
  security_message(data:report);
  exit(0);
}
exit(0);
