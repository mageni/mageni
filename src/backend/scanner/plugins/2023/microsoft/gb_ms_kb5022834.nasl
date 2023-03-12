# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.832006");
  script_version("2023-02-16T10:08:32+0000");
  script_cve_id("CVE-2023-21823", "CVE-2023-23376", "CVE-2023-21805", "CVE-2023-21702",
                "CVE-2023-21701", "CVE-2023-21700", "CVE-2023-21699", "CVE-2023-21697",
                "CVE-2023-21695", "CVE-2023-21694", "CVE-2023-21693", "CVE-2023-21692",
                "CVE-2023-21691", "CVE-2023-21690", "CVE-2023-21689", "CVE-2023-21688",
                "CVE-2023-21686", "CVE-2023-21685", "CVE-2023-21822", "CVE-2023-21820",
                "CVE-2023-21819", "CVE-2023-21818", "CVE-2023-21817", "CVE-2023-21816",
                "CVE-2023-21813", "CVE-2023-21812", "CVE-2023-21811", "CVE-2023-21804",
                "CVE-2023-21803", "CVE-2023-21802", "CVE-2023-21801", "CVE-2023-21799",
                "CVE-2023-21798", "CVE-2023-21797", "CVE-2023-21684");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-15 09:40:31 +0530 (Wed, 15 Feb 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5022834)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5022834");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution Vulnerability in Windows MSHTML Platform.

  - A Denial of Service Vulnerability in Windows iSCSI Service.

  - A Denial of Service Vulnerability in Microsoft Protected Extensible Authentication Protocol.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 20H2 for x64-based Systems

  - Microsoft Windows 10 Version 20H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5022834");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)){
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build){
  exit(0);
}

if(!("19042" >< build || "19044" >< build || "19045" >< build)){
  exit(0);
}
dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.19041.2604"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 10.0.19041.2604");
  security_message(data:report);
  exit(0);
}
exit(99);