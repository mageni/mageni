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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814843");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-0555", "CVE-2019-0595", "CVE-2019-0596", "CVE-2019-0597",
                "CVE-2019-0598", "CVE-2019-0599", "CVE-2019-0600", "CVE-2019-0601",
                "CVE-2019-0602", "CVE-2019-0606", "CVE-2019-0615", "CVE-2019-0616",
                "CVE-2019-0618", "CVE-2019-0619", "CVE-2019-0621", "CVE-2019-0623",
                "CVE-2019-0625", "CVE-2019-0626", "CVE-2019-0628", "CVE-2019-0630",
                "CVE-2019-0633", "CVE-2019-0635", "CVE-2019-0636", "CVE-2019-0654",
                "CVE-2019-0656", "CVE-2019-0660", "CVE-2019-0662", "CVE-2019-0664",
                "CVE-2019-0676");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 15:18:39 +0530 (Wed, 13 Feb 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4487000)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4487000");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists

  - When the Windows Jet Database Engine improperly handles objects in memory.

  - When the Windows GDI component improperly discloses the contents of its memory.

  - When Internet Explorer improperly handles objects in memory.

  - In the way that the Microsoft Server Message Block 2.0 (SMBv2) server handles
    certain requests...

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to elevate privileges, execute arbitrary code, read unauthorized
  information and cause spoofing attacks.");

  script_tag(name:"affected", value:"Windows 8.1 for 32-bit/x64,

  Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4487000/windows-8-1-update-kb4487000");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Msi.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"5.0.9600.19268"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Msi.dll",
                            file_version:fileVer, vulnerable_range:"Less than 5.0.9600.19268");
  security_message(data:report);
  exit(0);
}
exit(99);
