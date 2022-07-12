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
  script_oid("1.3.6.1.4.1.25623.1.0.821103");
  script_version("2022-04-20T03:02:11+0000");
  script_cve_id("CVE-2022-21983", "CVE-2022-22008", "CVE-2022-24474", "CVE-2022-24479",
                "CVE-2022-24481", "CVE-2022-24482", "CVE-2022-24483", "CVE-2022-24484",
                "CVE-2022-24485", "CVE-2022-24486", "CVE-2022-24487", "CVE-2022-24489",
                "CVE-2022-24490", "CVE-2022-24491", "CVE-2022-24492", "CVE-2022-24493",
                "CVE-2022-24494", "CVE-2022-24495", "CVE-2022-24496", "CVE-2022-24497",
                "CVE-2022-24498", "CVE-2022-24499", "CVE-2022-24500", "CVE-2022-24521",
                "CVE-2022-24527", "CVE-2022-24528", "CVE-2022-24530", "CVE-2022-24533",
                "CVE-2022-24534", "CVE-2022-24536", "CVE-2022-24537", "CVE-2022-24538",
                "CVE-2022-24539", "CVE-2022-24540", "CVE-2022-24541", "CVE-2022-24542",
                "CVE-2022-24544", "CVE-2022-24545", "CVE-2022-24546", "CVE-2022-24547",
                "CVE-2022-24549", "CVE-2022-24550", "CVE-2022-26783", "CVE-2022-26784",
                "CVE-2022-26785", "CVE-2022-26786", "CVE-2022-26787", "CVE-2022-26788",
                "CVE-2022-26789", "CVE-2022-26790", "CVE-2022-26792", "CVE-2022-26793",
                "CVE-2022-26794", "CVE-2022-26795", "CVE-2022-26796", "CVE-2022-26797",
                "CVE-2022-26798", "CVE-2022-26801", "CVE-2022-26802", "CVE-2022-26803",
                "CVE-2022-26807", "CVE-2022-26808", "CVE-2022-26809", "CVE-2022-26810",
                "CVE-2022-26811", "CVE-2022-26812", "CVE-2022-26813", "CVE-2022-26814",
                "CVE-2022-26815", "CVE-2022-26816", "CVE-2022-26817", "CVE-2022-26818",
                "CVE-2022-26819", "CVE-2022-26820", "CVE-2022-26821", "CVE-2022-26822",
                "CVE-2022-26823", "CVE-2022-26824", "CVE-2022-26825", "CVE-2022-26826",
                "CVE-2022-26827", "CVE-2022-26828", "CVE-2022-26829", "CVE-2022-26831",
                "CVE-2022-26903", "CVE-2022-26904", "CVE-2022-26914", "CVE-2022-26915",
                "CVE-2022-26916", "CVE-2022-26917", "CVE-2022-26918", "CVE-2022-26919",
                "CVE-2022-26920");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-20 10:08:00 +0000 (Wed, 20 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 20:33:00 +0000 (Mon, 18 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-13 10:21:37 +0530 (Wed, 13 Apr 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5012647)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5012647");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Print Spooler.

  - A Remote Code Execution Vulnerability in Windows Network File System.

  - A Denial of Service Vulnerability in Windows LDAP.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5012647");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0){
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.2802"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.2802");
  security_message(data:report);
  exit(0);
}
exit(99);
