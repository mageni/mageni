# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.818927");
  script_version("2021-12-21T05:52:49+0000");
  script_cve_id("CVE-2021-41333", "CVE-2021-43207", "CVE-2021-43215", "CVE-2021-43216",
                "CVE-2021-43217", "CVE-2021-43219", "CVE-2021-43222", "CVE-2021-43223",
                "CVE-2021-43224", "CVE-2021-43226", "CVE-2021-43227", "CVE-2021-43228",
                "CVE-2021-43229", "CVE-2021-43230", "CVE-2021-43231", "CVE-2021-43232",
                "CVE-2021-43233", "CVE-2021-43234", "CVE-2021-43235", "CVE-2021-43236",
                "CVE-2021-43237", "CVE-2021-43238", "CVE-2021-43240", "CVE-2021-43244",
                "CVE-2021-43246", "CVE-2021-43247", "CVE-2021-43248", "CVE-2021-43883",
                "CVE-2021-43893");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-12-21 05:52:49 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-15 15:57:04 +0530 (Wed, 15 Dec 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5008206)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5008206");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Encrypting File System (EFS).

  - An RCE vulnerability in Windows Encrypting File System (EFS).

  - A memory corruption vulnerability in iSNS Server.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, disclose sensitive information and conduct
  remote code execution.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5008206");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.1976"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.18362.0 - 10.0.18362.1976");
  security_message(data:report);
  exit(0);
}
exit(99);
