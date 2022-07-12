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
  script_oid("1.3.6.1.4.1.25623.1.0.815088");
  script_version("2019-06-12T13:47:22+0000");
  script_cve_id("CVE-2019-0620", "CVE-2019-0710", "CVE-2019-0711", "CVE-2019-0713",
                "CVE-2019-0722", "CVE-2019-0888", "CVE-2019-0904", "CVE-2019-0905",
                "CVE-2019-0906", "CVE-2019-0907", "CVE-2019-0908", "CVE-2019-0909",
                "CVE-2019-0920", "CVE-2019-0941", "CVE-2019-0943", "CVE-2019-0948",
                "CVE-2019-0959", "CVE-2019-0972", "CVE-2019-0973", "CVE-2019-0974",
                "CVE-2019-0983", "CVE-2019-0984", "CVE-2019-0986", "CVE-2019-0988",
                "CVE-2019-0989", "CVE-2019-0990", "CVE-2019-0991", "CVE-2019-0992",
                "CVE-2019-0993", "CVE-2019-0998", "CVE-2019-1003", "CVE-2019-1005",
                "CVE-2019-1007", "CVE-2019-1010", "CVE-2019-1012", "CVE-2019-1014",
                "CVE-2019-1017", "CVE-2019-1018", "CVE-2019-1019", "CVE-2019-1021",
                "CVE-2019-1022", "CVE-2019-1023", "CVE-2019-1024", "CVE-2019-1025",
                "CVE-2019-1026", "CVE-2019-1027", "CVE-2019-1028", "CVE-2019-1038",
                "CVE-2019-1039", "CVE-2019-1040", "CVE-2019-1041", "CVE-2019-1043",
                "CVE-2019-1044", "CVE-2019-1046", "CVE-2019-1050", "CVE-2019-1051",
                "CVE-2019-1052", "CVE-2019-1053", "CVE-2019-1054", "CVE-2019-1055",
                "CVE-2019-1064", "CVE-2019-1065", "CVE-2019-1069", "CVE-2019-1080",
                "CVE-2019-1081", "CVE-2019-2102", "CVE-2019-9500", "CVE-2019-9501",
                "CVE-2019-9502", "CVE-2019-9503");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-12 13:47:22 +0000 (Wed, 12 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-12 09:36:13 +0530 (Wed, 12 Jun 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4503327)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4503327");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Windows kernel improperly initializes objects in memory.

  - Chakra scripting engine handles objects in memory in Microsoft Edge.

  - Microsoft Hyper-V on a host server fails to properly validate input from
    a privileged user on a guest operating system.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows AppX Deployment Service (AppXSVC) improperly handles hard links.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows Common Log File System (CLFS) driver improperly handles objects in
    memory.

  - For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on a victim system, escalate privileges, bypass
  security restrictions, disclose sensitive information and cause a denial of
  service condition on a victim system.");

  script_tag(name:"affected", value:"Windows 10 Version 1809 for 32-bit Systems

  Windows 10 Version 1809 for x64-based Systems

  Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4503327");
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

if(version_in_range(version:edgeVer, test_version:"11.0.17763.0", test_version2:"11.0.17763.556"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17763.0 - 11.0.17763.556");
  security_message(data:report);
  exit(0);
}
exit(99);
