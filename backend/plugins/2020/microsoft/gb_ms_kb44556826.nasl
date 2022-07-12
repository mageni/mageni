# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817021");
  script_version("2020-05-13T15:33:42+0000");
  script_cve_id("CVE-2020-1157", "CVE-2020-1010", "CVE-2020-1021", "CVE-2020-1048",
                "CVE-2020-1051", "CVE-2020-1124", "CVE-2020-1112", "CVE-2020-1113",
                "CVE-2020-1114", "CVE-2020-1153", "CVE-2020-1125", "CVE-2020-1156",
                "CVE-2020-1154", "CVE-2020-1149", "CVE-2020-1076", "CVE-2020-1067",
                "CVE-2020-1068", "CVE-2020-1071", "CVE-2020-1054", "CVE-2020-1072",
                "CVE-2020-1079", "CVE-2020-1070", "CVE-2020-1131", "CVE-2020-1078",
                "CVE-2020-1144", "CVE-2020-1088", "CVE-2020-1179", "CVE-2020-0909",
                "CVE-2020-0963", "CVE-2020-1116", "CVE-2020-1123", "CVE-2020-1132",
                "CVE-2020-1164", "CVE-2020-1143", "CVE-2020-1141", "CVE-2020-1139",
                "CVE-2020-1061", "CVE-2020-1136", "CVE-2020-1081", "CVE-2020-1134",
                "CVE-2020-1082", "CVE-2020-1084", "CVE-2020-1086", "CVE-2020-1174",
                "CVE-2020-1175", "CVE-2020-1176", "CVE-2020-1035", "CVE-2020-1060",
                "CVE-2020-1062", "CVE-2020-1093", "CVE-2020-1108", "CVE-2020-1037",
                "CVE-2020-1058", "CVE-2020-1064", "CVE-2020-1092");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-14 10:20:05 +0000 (Thu, 14 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-13 18:25:45 +0530 (Wed, 13 May 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4556826)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4556826");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error in the way that the scripting engine handles objects in memory
    in Internet Explorer.

  - Multiple errors when the Microsoft Windows Graphics Component improperly
    handles objects in memory.

  - An error when the Windows Jet Database Engine improperly handles objects
    in memory.

  - An error when the Windows update stack fails to properly handle objects in
    memory.

  - An error when the Windows Delivery Optimization service improperly handles
    objects in memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, disclose sensitive information and
  conduct denial of service attacks.");

  script_tag(name:"affected", value:"Windows 10 for 32-bit Systems

  Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4556826");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Usermgr.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.18574"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Kernel32.dll",
                            file_version:dllVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.18574");
  security_message(data:report);
  exit(0);
}
exit(99);
