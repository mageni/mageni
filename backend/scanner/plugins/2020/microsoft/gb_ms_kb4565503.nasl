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
  script_oid("1.3.6.1.4.1.25623.1.0.817224");
  script_version("2020-07-16T11:59:37+0000");
  script_cve_id("CVE-2019-1469", "CVE-2020-1085", "CVE-2020-1249", "CVE-2020-1267",
                "CVE-2020-1330", "CVE-2020-1333", "CVE-2020-1336", "CVE-2020-1344",
                "CVE-2020-1347", "CVE-2020-1350", "CVE-2020-1351", "CVE-2020-1352",
                "CVE-2020-1353", "CVE-2020-1354", "CVE-2020-1355", "CVE-2020-1356",
                "CVE-2020-1357", "CVE-2020-1358", "CVE-2020-1359", "CVE-2020-1360",
                "CVE-2020-1361", "CVE-2020-1362", "CVE-2020-1363", "CVE-2020-1364",
                "CVE-2020-1365", "CVE-2020-1366", "CVE-2020-1367", "CVE-2020-1368",
                "CVE-2020-1369", "CVE-2020-1370", "CVE-2020-1371", "CVE-2020-1372",
                "CVE-2020-1373", "CVE-2020-1374", "CVE-2020-1375", "CVE-2020-1381",
                "CVE-2020-1382", "CVE-2020-1384", "CVE-2020-1385", "CVE-2020-1386",
                "CVE-2020-1387", "CVE-2020-1388", "CVE-2020-1389", "CVE-2020-1390",
                "CVE-2020-1391", "CVE-2020-1392", "CVE-2020-1393", "CVE-2020-1394",
                "CVE-2020-1395", "CVE-2020-1396", "CVE-2020-1397", "CVE-2020-1398",
                "CVE-2020-1399", "CVE-2020-1400", "CVE-2020-1401", "CVE-2020-1402",
                "CVE-2020-1403", "CVE-2020-1404", "CVE-2020-1405", "CVE-2020-1406",
                "CVE-2020-1407", "CVE-2020-1408", "CVE-2020-1409", "CVE-2020-1410",
                "CVE-2020-1411", "CVE-2020-1412", "CVE-2020-1413", "CVE-2020-1414",
                "CVE-2020-1415", "CVE-2020-1418", "CVE-2020-1419", "CVE-2020-1420",
                "CVE-2020-1421", "CVE-2020-1422", "CVE-2020-1423", "CVE-2020-1424",
                "CVE-2020-1426", "CVE-2020-1427", "CVE-2020-1428", "CVE-2020-1429",
                "CVE-2020-1430", "CVE-2020-1431", "CVE-2020-1432", "CVE-2020-1433",
                "CVE-2020-1434", "CVE-2020-1435", "CVE-2020-1436", "CVE-2020-1437",
                "CVE-2020-1438", "CVE-2020-1462", "CVE-2020-1463", "CVE-2020-1468");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-17 15:02:17 +0000 (Fri, 17 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-15 12:33:34 +0530 (Wed, 15 Jul 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4565503)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4565503");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Windows System Events Broker fails to properly handle file operations.

  - Windows WalletService fails to properly handle objects in memory.

  - Windows Mobile Device Management (MDM) Diagnostics fails to
    properly handle objects in memory.

  - Windows Jet Database Engine fails to properly handle objects in memory.

  - Windows Network Connections Service fails to properly handle
    objects in memory.

  - SharedStream Library fails to handle objects in memory.
  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, disclose sensitive information
  and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4565503");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

dllPath = smb_get_system32root();
if(!dllPath)
  exit(0);

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Gdiplus.dll");
if(!fileVer)
  exit(0);

if(version_in_range(version:fileVer, test_version:"10.0.19041.0", test_version2:"10.0.19041.387")) {
  report = report_fixed_ver(file_checked:dllPath + "\Gdiplus.dll",
                            file_version:fileVer, vulnerable_range:"10.0.19041.0 - 10.0.19041.387");
  security_message(data:report);
  exit(0);
}

exit(99);
