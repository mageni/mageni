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
  script_oid("1.3.6.1.4.1.25623.1.0.815409");
  script_version("2019-07-10T14:00:44+0000");
  script_cve_id("CVE-2019-0880", "CVE-2019-0887", "CVE-2019-1102", "CVE-2019-0999",
                "CVE-2019-1001", "CVE-2019-1004", "CVE-2019-1103", "CVE-2019-1104",
                "CVE-2019-1107", "CVE-2019-1006", "CVE-2019-1108", "CVE-2019-1113",
                "CVE-2019-1056", "CVE-2019-1059", "CVE-2019-1062", "CVE-2019-1063",
                "CVE-2019-1067", "CVE-2019-1071", "CVE-2019-1073", "CVE-2019-1130",
                "CVE-2019-1082", "CVE-2019-1083", "CVE-2019-1085", "CVE-2019-1086",
                "CVE-2019-1087", "CVE-2019-1088", "CVE-2019-1089", "CVE-2019-1091",
                "CVE-2019-1092", "CVE-2019-1095", "CVE-2019-1096", "CVE-2019-1097",
                "CVE-2019-1093", "CVE-2019-1094", "CVE-2019-0683");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-10 14:00:44 +0000 (Wed, 10 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-10 08:44:05 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4507458)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4507458");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Scripting engine improperly handles objects in memory in Microsoft browsers.

  - Windows RDP client improperly discloses the contents of its memory.

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - Windows Graphics Device Interface (GDI) improperly handles objects in the memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code in kernel mode, elevate privileges
  by escaping a sandbox, gain access to sensitive information and conduct
  denial-of-service.");

  script_tag(name:"affected", value:"Windows 10 for 32-bit Systems

  Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4507458");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.18274"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.10240.0 - 11.0.10240.18274");
  security_message(data:report);
  exit(0);
}
exit(99);
