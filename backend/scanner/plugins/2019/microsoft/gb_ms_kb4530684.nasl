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
  script_oid("1.3.6.1.4.1.25623.1.0.815683");
  script_version("2019-12-11T13:23:17+0000");
  script_cve_id("CVE-2018-0859", "CVE-2019-0838", "CVE-2019-0860", "CVE-2019-1453",
                "CVE-2019-1465", "CVE-2019-1466", "CVE-2019-1467", "CVE-2019-1468",
                "CVE-2019-1469", "CVE-2019-1470", "CVE-2019-1471", "CVE-2019-1472",
                "CVE-2019-1474", "CVE-2019-1476", "CVE-2019-1483", "CVE-2019-1484",
                "CVE-2019-1485", "CVE-2019-1488");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-11 13:23:17 +0000 (Wed, 11 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-11 13:58:15 +0530 (Wed, 11 Dec 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4530684)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4530684");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error when Windows Hyper-V on a host server fails to properly validate
    input from an authenticated user on a guest operating system.

  - An error when the Windows kernel improperly handles objects in memory.

  - An error when Microsoft Defender improperly handles specific buffers.

  - An error when the Windows GDI component improperly discloses the contents
    of its memory.

  - An error when Microsoft Windows OLE fails to properly validate user input.

  - An error in the way that the VBScript engine handles objects in memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, gain access to potentially sensitive information,
  trigger false positives for threat, escalate privileges, cause the RDP
  service on the target system to stop responding.");

  script_tag(name:"affected", value:"Windows 10 Version 1903 for 32-bit Systems

  Windows 10 Version 1903 for x64-based Systems

  Windows 10 Version 1909 for 32-bit Systems

  Windows 10 Version 1909 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4530684");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Chakra.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"11.0.18362.0", test_version2:"11.0.18362.534"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Chakra.dll",
                            file_version:fileVer, vulnerable_range:"11.0.18362.0 - 11.0.18362.534");
  security_message(data:report);
  exit(0);
}
exit(99);
