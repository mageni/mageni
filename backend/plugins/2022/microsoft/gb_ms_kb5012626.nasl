# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.820077");
  script_version("2022-04-20T08:12:51+0000");
  script_cve_id("CVE-2022-21983", "CVE-2022-24474", "CVE-2022-24481", "CVE-2022-24485",
                "CVE-2022-24492", "CVE-2022-24493", "CVE-2022-24494", "CVE-2022-24498",
                "CVE-2022-24499", "CVE-2022-24500", "CVE-2022-24521", "CVE-2022-24527",
                "CVE-2022-24528", "CVE-2022-24530", "CVE-2022-24533", "CVE-2022-24534",
                "CVE-2022-24536", "CVE-2022-24540", "CVE-2022-24541", "CVE-2022-24542",
                "CVE-2022-24544", "CVE-2022-26787", "CVE-2022-26790", "CVE-2022-26792",
                "CVE-2022-26794", "CVE-2022-26796", "CVE-2022-26797", "CVE-2022-26798",
                "CVE-2022-26801", "CVE-2022-26802", "CVE-2022-26803", "CVE-2022-26807",
                "CVE-2022-26809", "CVE-2022-26810", "CVE-2022-26812", "CVE-2022-26813",
                "CVE-2022-26815", "CVE-2022-26819", "CVE-2022-26820", "CVE-2022-26821",
                "CVE-2022-26822", "CVE-2022-26827", "CVE-2022-26829", "CVE-2022-26831",
                "CVE-2022-26903", "CVE-2022-26904", "CVE-2022-26915", "CVE-2022-26916",
                "CVE-2022-26917", "CVE-2022-26918", "CVE-2022-26919");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-20 10:08:00 +0000 (Wed, 20 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-14 12:24:01 +0530 (Thu, 14 Apr 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5012626)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5012626");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A remote code execution vulnerability in Windows DNS Server.

  - An elevation of privilege vulnerability in Windows Print Spooler.

  - An elevation of privilege vulnerability in Windows File Server Resource Management Service.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, disclose sensitive information, conduct remote code execution,
  and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5012626");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2008r2:2, win7x64:2, win7:2) <= 0){
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

if(version_is_less(version:fileVer, test_version:"6.1.7601.25920"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.25920");
  security_message(data:report);
  exit(0);
}
exit(99);
