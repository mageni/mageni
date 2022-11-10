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
  script_oid("1.3.6.1.4.1.25623.1.0.826628");
  script_version("2022-11-09T13:25:33+0000");
  script_cve_id("CVE-2022-23824", "CVE-2022-37966", "CVE-2022-37967", "CVE-2022-37992",
                "CVE-2022-38015", "CVE-2022-38023", "CVE-2022-41039", "CVE-2022-41045",
                "CVE-2022-41047", "CVE-2022-41048", "CVE-2022-41049", "CVE-2022-41050",
                "CVE-2022-41052", "CVE-2022-41053", "CVE-2022-41054", "CVE-2022-41055",
                "CVE-2022-41056", "CVE-2022-41057", "CVE-2022-41058", "CVE-2022-41073",
                "CVE-2022-41086", "CVE-2022-41088", "CVE-2022-41090", "CVE-2022-41091",
                "CVE-2022-41093", "CVE-2022-41095", "CVE-2022-41096", "CVE-2022-41097",
                "CVE-2022-41098", "CVE-2022-41099", "CVE-2022-41100", "CVE-2022-41101",
                "CVE-2022-41102", "CVE-2022-41109", "CVE-2022-41113", "CVE-2022-41118",
                "CVE-2022-41125", "CVE-2022-41128");
  script_tag(name:"cvss_base", value:"7.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-11-09 13:25:33 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-09 10:02:34 +0530 (Wed, 09 Nov 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5019966)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5019966");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Advanced Local Procedure Call (ALPC) Elevation of Privilege Vulnerability.

  - Windows Win32k Elevation of Privilege Vulnerability.

  - Network Policy Server (NPS) RADIUS Protocol Information Disclosure Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions and conduct DoSattacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5019966");
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.3649"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.3649");
  security_message(data:report);
  exit(0);
}
exit(99);
