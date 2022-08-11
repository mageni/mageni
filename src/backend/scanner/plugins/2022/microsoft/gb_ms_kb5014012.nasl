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
  script_oid("1.3.6.1.4.1.25623.1.0.821111");
  script_version("2022-05-11T14:03:57+0000");
  script_cve_id("CVE-2022-21972", "CVE-2022-22011", "CVE-2022-22012", "CVE-2022-22013",
                "CVE-2022-22014", "CVE-2022-22015", "CVE-2022-22019", "CVE-2022-23270",
                "CVE-2022-26788", "CVE-2022-26925", "CVE-2022-26926", "CVE-2022-26931",
                "CVE-2022-26934", "CVE-2022-26935", "CVE-2022-26936", "CVE-2022-26937",
                "CVE-2022-29103", "CVE-2022-29105", "CVE-2022-29112", "CVE-2022-29115",
                "CVE-2022-29121", "CVE-2022-29127", "CVE-2022-29128", "CVE-2022-29129",
                "CVE-2022-29130", "CVE-2022-29132", "CVE-2022-29137", "CVE-2022-29139",
                "CVE-2022-29141");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-12 09:56:58 +0000 (Thu, 12 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 16:29:00 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 12:42:37 +0530 (Wed, 11 May 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5014012)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5014012");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Kerberos.

  - A Remote Code Execution Vulnerability in Windows Network File System.

  - A Denial of Service Vulnerability in Windows WLAN AutoConfig Service.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing attacks and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5014012");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.25954"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.25954");
  security_message(data:report);
  exit(0);
}
exit(99);
