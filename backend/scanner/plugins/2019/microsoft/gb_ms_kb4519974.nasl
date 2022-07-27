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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815492");
  script_version("2019-10-09T12:58:40+0000");
  script_cve_id("CVE-2019-0608", "CVE-2019-1238", "CVE-2019-1357", "CVE-2019-1371",
                "CVE-2019-1367", "CVE-2019-1192");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-09 12:58:40 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-09 10:13:33 +0530 (Wed, 09 Oct 2019)");
  script_name("Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4519974)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4519974");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Microsoft Browsers does not properly parse HTTP content.

  - VBScript engine improperly handles objects in memory.

  - Microsoft Browsers improperly handle browser cookies.

  - Internet Explorer improperly accesses objects in memory.

  - Scripting engine handles objects in memory in Internet Explorer.

  - Microsoft browsers improperly handle requests of different origins.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code on the client machine, bypass security restrictions
  and conduct spoofing attack.");

  script_tag(name:"affected", value:"Windows Server 2012");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4519974");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "MS/IE/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^11\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(version_is_less(version:iedllVer, test_version:"11.0.9600.19502"))
{
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll",
                            file_version:iedllVer, vulnerable_range:"Less than 11.0.9600.19502");
  security_message(data:report);
  exit(0);
}
exit(0);
