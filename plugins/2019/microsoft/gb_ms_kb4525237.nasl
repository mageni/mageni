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
  script_oid("1.3.6.1.4.1.25623.1.0.815837");
  script_version("2019-11-14T06:01:26+0000");
  script_cve_id("CVE-2018-12207", "CVE-2019-0712", "CVE-2019-0719", "CVE-2019-0721",
                "CVE-2019-11135", "CVE-2019-1309", "CVE-2019-1310", "CVE-2019-1324",
                "CVE-2019-1374", "CVE-2019-1380", "CVE-2019-1381", "CVE-2019-1382",
                "CVE-2019-1383", "CVE-2019-1384", "CVE-2019-1385", "CVE-2019-1388",
                "CVE-2019-1389", "CVE-2019-1390", "CVE-2019-1391", "CVE-2019-1393",
                "CVE-2019-1394", "CVE-2019-1395", "CVE-2019-1396", "CVE-2019-1397",
                "CVE-2019-1398", "CVE-2019-1399", "CVE-2019-1405", "CVE-2019-1406",
                "CVE-2019-1407", "CVE-2019-1408", "CVE-2019-1409", "CVE-2019-1411",
                "CVE-2019-1413", "CVE-2019-1415", "CVE-2019-1416", "CVE-2019-1417",
                "CVE-2019-1418", "CVE-2019-1419", "CVE-2019-1420", "CVE-2019-1422",
                "CVE-2019-1424", "CVE-2019-1426", "CVE-2019-1428", "CVE-2019-1429",
                "CVE-2019-1433", "CVE-2019-1435", "CVE-2019-1436", "CVE-2019-1438",
                "CVE-2019-1439", "CVE-2019-1440", "CVE-2019-1456");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-11-14 06:01:26 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-13 10:37:52 +0530 (Wed, 13 Nov 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4525237)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4525237");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Microsoft Hyper-V Network Switch on a host server fails to properly validate
    input from a privileged user on a guest operating system.

  - Windows Installer improperly handles certain filesystem operations.

  - Windows Error Reporting (WER) improperly handles objects in memory.

  - Windows TCP/IP stack improperly handles IPv6 flowlabel filled in packets.

  - The win32k component improperly provides kernel information.

  - Windows Universal Plug and Play (UPnP) service improperly allows COM object
    creation.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows Graphics Component improperly handles objects in memory.

  - Scripting engine improperly handles objects in memory in Microsoft Edge
    (HTML-based).

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to crash host server, execute code with elevated permissions, obtain information
  to further compromise the user's system, elevate privileges on an affected system
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Windows 10 Version 1803 for 32-bit Systems

  Windows 10 Version 1803 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4525237");
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

if(version_in_range(version:edgeVer, test_version:"11.0.17134.0", test_version2:"11.0.17134.1129"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17134.0 - 11.0.17134.1129");
  security_message(data:report);
  exit(0);
}
exit(99);
