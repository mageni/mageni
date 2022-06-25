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
  script_oid("1.3.6.1.4.1.25623.1.0.815463");
  script_version("2019-09-11T14:33:42+0000");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091",
                "CVE-2019-1208", "CVE-2019-1214", "CVE-2019-1215", "CVE-2019-1219",
                "CVE-2019-1220", "CVE-2019-1235", "CVE-2019-1236", "CVE-2019-1240",
                "CVE-2019-1241", "CVE-2019-1242", "CVE-2019-1243", "CVE-2019-1244",
                "CVE-2019-1245", "CVE-2019-1246", "CVE-2019-1247", "CVE-2019-1248",
                "CVE-2019-1249", "CVE-2019-1250", "CVE-2019-1252", "CVE-2019-1256",
                "CVE-2019-1268", "CVE-2019-1271", "CVE-2019-1274", "CVE-2019-1280",
                "CVE-2019-1282", "CVE-2019-1284", "CVE-2019-1285", "CVE-2019-1286",
                "CVE-2019-1291");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-11 14:33:42 +0000 (Wed, 11 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-11 12:08:05 +0530 (Wed, 11 Sep 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4516026)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4516026.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error in Windows Text Service Framework (TSF) when the TSF server process
    does not validate the source of input or commands it receives.

  - VBScript engine improperly handles objects in memory.

  - Windows Jet Database Engine improperly handles objects in memory.

  - DirectWrite improperly discloses the contents of its memory.

  - Windows Jet Database Engine improperly handles objects in memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code on a victim system, obtain information
  to further compromise the user's system, gain elevated privileges and disclose
  sensitive information.");

  script_tag(name:"affected", value:"Windows Server 2008 for 32-bit Systems Service Pack 2,

  Windows Server 2008 for x64-based Systems Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4516026");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

ntlVer = fetch_file_version(sysPath:sysPath, file_name:"Ntoskrnl.exe");
if(!ntlVer)
  exit(0);

if(version_is_less(version:ntlVer, test_version:"6.0.6003.20625"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Ntoskrnl.exe",
                            file_version:ntlVer, vulnerable_range:"Less than 6.0.6003.20625");
  security_message(data:report);
  exit(0);
}
exit(99);
