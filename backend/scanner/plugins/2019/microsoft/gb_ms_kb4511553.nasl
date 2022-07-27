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
  script_oid("1.3.6.1.4.1.25623.1.0.815437");
  script_version("2019-08-14T14:30:23+0000");
  script_cve_id("CVE-2019-0714", "CVE-2019-0715", "CVE-2019-1168", "CVE-2019-1170",
                "CVE-2019-1171", "CVE-2019-1172", "CVE-2019-0716", "CVE-2019-0717",
                "CVE-2019-0718", "CVE-2019-0720", "CVE-2019-0723", "CVE-2019-1173",
                "CVE-2019-1174", "CVE-2019-1175", "CVE-2019-1176", "CVE-2019-1177",
                "CVE-2019-0965", "CVE-2019-1030", "CVE-2019-1057", "CVE-2019-1178",
                "CVE-2019-1179", "CVE-2019-1180", "CVE-2019-1078", "CVE-2019-1131",
                "CVE-2019-1133", "CVE-2019-1139", "CVE-2019-1140", "CVE-2019-1181",
                "CVE-2019-1182", "CVE-2019-1183", "CVE-2019-1184", "CVE-2019-1145",
                "CVE-2019-1146", "CVE-2019-1192", "CVE-2019-1193", "CVE-2019-1194",
                "CVE-2019-1147", "CVE-2019-1148", "CVE-2019-1149", "CVE-2019-1195",
                "CVE-2019-1196", "CVE-2019-1197", "CVE-2019-1198", "CVE-2019-1150",
                "CVE-2019-1151", "CVE-2019-1206", "CVE-2019-1212", "CVE-2019-1222",
                "CVE-2019-1223", "CVE-2019-1152", "CVE-2019-1153", "CVE-2019-1224",
                "CVE-2019-1225", "CVE-2019-1226", "CVE-2019-1227", "CVE-2019-9506",
                "CVE-2019-1155", "CVE-2019-1156", "CVE-2019-1157", "CVE-2019-9511",
                "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9518",
                "CVE-2019-1158", "CVE-2019-1159", "CVE-2019-1162", "CVE-2019-1163",
                "CVE-2019-1164", "CVE-2019-1141", "CVE-2019-1143", "CVE-2019-1144",
                "CVE-2019-1186", "CVE-2019-1187", "CVE-2019-1188", "CVE-2019-1190");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-14 14:30:23 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 09:56:24 +0530 (Wed, 14 Aug 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4511553)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4511553");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - Windows improperly handles objects in memory.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows font library improperly handles specially crafted embedded
    fonts.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - Windows Jet Database Engine improperly handles objects in memory.

  - The Chakra scripting engine handles objects in memory in Microsoft Edge.

  - Windows RDP server improperly discloses the contents of its memory.

  - Windows kernel fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode, obtain information to further compromise
  a user's system, elevate permissions and create a denial of service condition
  causing the target system to become unresponsive.");

  script_tag(name:"affected", value:"Windows 10 Version 1809 for x64-based Systems

  Windows Server 2019

  Windows 10 Version 1809 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4511553");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0){
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

if(version_in_range(version:edgeVer, test_version:"11.0.17763.0", test_version2:"11.0.17763.677"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17763.0 - 11.0.17763.677");
  security_message(data:report);
  exit(0);
}
exit(99);
