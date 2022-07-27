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
  script_oid("1.3.6.1.4.1.25623.1.0.817140");
  script_version("2020-06-10T15:24:55+0000");
  script_cve_id("CVE-2020-0915", "CVE-2020-0916", "CVE-2020-0986", "CVE-2020-1073",
                "CVE-2020-1160", "CVE-2020-1162", "CVE-2020-1194", "CVE-2020-1196",
                "CVE-2020-1197", "CVE-2020-1199", "CVE-2020-1201", "CVE-2020-1202",
                "CVE-2020-1203", "CVE-2020-1204", "CVE-2020-1206", "CVE-2020-1207",
                "CVE-2020-1208", "CVE-2020-1209", "CVE-2020-1211", "CVE-2020-1212",
                "CVE-2020-1213", "CVE-2020-1214", "CVE-2020-1215", "CVE-2020-1216",
                "CVE-2020-1217", "CVE-2020-1219", "CVE-2020-1220", "CVE-2020-1222",
                "CVE-2020-1230", "CVE-2020-1231", "CVE-2020-1232", "CVE-2020-1233",
                "CVE-2020-1234", "CVE-2020-1235", "CVE-2020-1236", "CVE-2020-1237",
                "CVE-2020-1238", "CVE-2020-1239", "CVE-2020-1241", "CVE-2020-1242",
                "CVE-2020-1244", "CVE-2020-1246", "CVE-2020-1247", "CVE-2020-1248",
                "CVE-2020-1251", "CVE-2020-1253", "CVE-2020-1254", "CVE-2020-1255",
                "CVE-2020-1257", "CVE-2020-1258", "CVE-2020-1259", "CVE-2020-1260",
                "CVE-2020-1261", "CVE-2020-1262", "CVE-2020-1263", "CVE-2020-1264",
                "CVE-2020-1265", "CVE-2020-1266", "CVE-2020-1268", "CVE-2020-1269",
                "CVE-2020-1270", "CVE-2020-1271", "CVE-2020-1272", "CVE-2020-1273",
                "CVE-2020-1274", "CVE-2020-1275", "CVE-2020-1276", "CVE-2020-1277",
                "CVE-2020-1278", "CVE-2020-1279", "CVE-2020-1280", "CVE-2020-1281",
                "CVE-2020-1282", "CVE-2020-1283", "CVE-2020-1286", "CVE-2020-1287",
                "CVE-2020-1290", "CVE-2020-1291", "CVE-2020-1292", "CVE-2020-1293",
                "CVE-2020-1294", "CVE-2020-1296", "CVE-2020-1299", "CVE-2020-1300",
                "CVE-2020-1301", "CVE-2020-1302", "CVE-2020-1304", "CVE-2020-1305",
                "CVE-2020-1306", "CVE-2020-1307", "CVE-2020-1309", "CVE-2020-1310",
                "CVE-2020-1311", "CVE-2020-1312", "CVE-2020-1313", "CVE-2020-1314",
                "CVE-2020-1315", "CVE-2020-1316", "CVE-2020-1317", "CVE-2020-1324",
                "CVE-2020-1334", "CVE-2020-1348");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-10 15:24:55 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-10 08:52:23 +0530 (Wed, 10 Jun 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4560960)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4560960");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error when the Windows kernel fails to properly handle objects in memory.

  - An error when the Windows GDI component improperly discloses the contents of its
    memory.

  - An error when the Windows Runtime improperly handles objects in memory.

  - An error in the way that the VBScript engine handles objects in memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, disclose sensitive information and
  conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1903 for 32-bit/x64-based Systems

  - Microsoft Windows 10 Version 1909 for 32-bit/x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4560960");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Kernel32.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.899"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Kernel32.dll",
                            file_version:fileVer, vulnerable_range:"10.0.18362.0 - 10.0.18362.899");
  security_message(data:report);
  exit(0);
}
exit(99);
