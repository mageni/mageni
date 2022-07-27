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
  script_oid("1.3.6.1.4.1.25623.1.0.815459");
  script_version("2019-09-11T14:33:42+0000");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-0787",
                "CVE-2019-0788", "CVE-2019-0928", "CVE-2019-11091", "CVE-2019-1138",
                "CVE-2019-1142", "CVE-2019-1208", "CVE-2019-1214", "CVE-2019-1215",
                "CVE-2019-1217", "CVE-2019-1219", "CVE-2019-1220", "CVE-2019-1221",
                "CVE-2019-1232", "CVE-2019-1235", "CVE-2019-1236", "CVE-2019-1237",
                "CVE-2019-1240", "CVE-2019-1241", "CVE-2019-1242", "CVE-2019-1243",
                "CVE-2019-1244", "CVE-2019-1245", "CVE-2019-1246", "CVE-2019-1247",
                "CVE-2019-1248", "CVE-2019-1249", "CVE-2019-1250", "CVE-2019-1251",
                "CVE-2019-1252", "CVE-2019-1253", "CVE-2019-1254", "CVE-2019-1256",
                "CVE-2019-1267", "CVE-2019-1268", "CVE-2019-1269", "CVE-2019-1270",
                "CVE-2019-1271", "CVE-2019-1272", "CVE-2019-1273", "CVE-2019-1274",
                "CVE-2019-1277", "CVE-2019-1278", "CVE-2019-1280", "CVE-2019-1282",
                "CVE-2019-1285", "CVE-2019-1286", "CVE-2019-1287", "CVE-2019-1289",
                "CVE-2019-1290", "CVE-2019-1291", "CVE-2019-1292", "CVE-2019-1293",
                "CVE-2019-1294", "CVE-2019-1298", "CVE-2019-1300", "CVE-2019-1303");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-11 14:33:42 +0000 (Wed, 11 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-11 10:55:50 +0530 (Wed, 11 Sep 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4516058)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4516058");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - Chakra scripting engine handles objects in memory in Microsoft Edge.

  - An error in Windows Text Service Framework (TSF) when the TSF server process
    does not validate the source of input or commands it receives.

  - Diagnostics Hub Standard Collector Service improperly impersonates certain
    file operations.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows Common Log File System (CLFS) driver improperly handles objects in
    memory.

  - Active Directory Federation Services (ADFS) does not properly sanitize
    certain error messages.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - An elevation of privilege exists in hdAudio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges, execute code with elevated permissions, obtain
  information to further compromise the user's system and cause a target
  system to stop responding.");

  script_tag(name:"affected", value:"Windows 10 Version 1803 for 32-bit Systems

  Windows 10 Version 1803 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4516058");
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

if(version_in_range(version:edgeVer, test_version:"11.0.17134.0", test_version2:"11.0.17134.1005"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17134.0 - 11.0.17134.1005");
  security_message(data:report);
  exit(0);
}
exit(99);
