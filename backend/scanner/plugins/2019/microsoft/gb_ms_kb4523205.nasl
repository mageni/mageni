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
  script_oid("1.3.6.1.4.1.25623.1.0.815835");
  script_version("2019-11-14T12:44:20+0000");
  script_cve_id("CVE-2018-12207", "CVE-2019-0712", "CVE-2019-0719", "CVE-2019-0721",
                "CVE-2019-11135", "CVE-2019-1309", "CVE-2019-1310", "CVE-2019-1324",
                "CVE-2019-1374", "CVE-2019-1379", "CVE-2019-1380", "CVE-2019-1381",
                "CVE-2019-1382", "CVE-2019-1383", "CVE-2019-1384", "CVE-2019-1385",
                "CVE-2019-1388", "CVE-2019-1390", "CVE-2019-1391", "CVE-2019-1393",
                "CVE-2019-1394", "CVE-2019-1395", "CVE-2019-1396", "CVE-2019-1397",
                "CVE-2019-1398", "CVE-2019-1399", "CVE-2019-1405", "CVE-2019-1406",
                "CVE-2019-1408", "CVE-2019-1409", "CVE-2019-1411", "CVE-2019-1413",
                "CVE-2019-1415", "CVE-2019-1416", "CVE-2019-1417", "CVE-2019-1418",
                "CVE-2019-1419", "CVE-2019-1420", "CVE-2019-1422", "CVE-2019-1424",
                "CVE-2019-1426", "CVE-2019-1427", "CVE-2019-1428", "CVE-2019-1429",
                "CVE-2019-1433", "CVE-2019-1435", "CVE-2019-1436", "CVE-2019-1437",
                "CVE-2019-1438", "CVE-2019-1439", "CVE-2019-1440", "CVE-2019-1456");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-11-14 12:44:20 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-13 09:08:41 +0530 (Wed, 13 Nov 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4523205)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4523205");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Windows DirectWrite improperly discloses the contents of its memory.

  - Microsoft Hyper-V Network Switch on a host server fails to properly validate
    input from a privileged user on a guest operating system.

  - Windows Installer improperly handles certain filesystem operations.

  - Windows Error Reporting (WER) improperly handles objects in memory.

  - Windows TCP/IP stack improperly handles IPv6 flowlabel filled in packets.

  - The win32k component improperly provides kernel information.

  - Windows Data Sharing Service improperly handles file operations.

  - Windows Universal Plug and Play (UPnP) service improperly allows COM object
    creation.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information, cause the host server to crash, execute code
  with elevated permissions, elevate privileges and bypass security restrictions.");

  script_tag(name:"affected", value:"Windows 10 Version 1809 for 32-bit Systems

  Windows 10 Version 1809 for x64-based Systems

  Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4523205");
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

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Userenv.dll");

if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.830"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Userenv.dll",
                            file_version:dllVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.830");
  security_message(data:report);
  exit(0);
}
exit(99);
