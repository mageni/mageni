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
  script_oid("1.3.6.1.4.1.25623.1.0.818952");
  script_version("2022-01-13T03:54:52+0000");
  script_cve_id("CVE-2022-21833", "CVE-2022-21834", "CVE-2022-21835", "CVE-2022-21836",
                "CVE-2022-21838", "CVE-2022-21843", "CVE-2022-21848", "CVE-2022-21850",
                "CVE-2022-21851", "CVE-2022-21857", "CVE-2022-21859", "CVE-2022-21862",
                "CVE-2022-21880", "CVE-2022-21883", "CVE-2022-21884", "CVE-2022-21885",
                "CVE-2022-21889", "CVE-2022-21890", "CVE-2022-21893", "CVE-2022-21897",
                "CVE-2022-21899", "CVE-2022-21900", "CVE-2022-21903", "CVE-2022-21904",
                "CVE-2022-21905", "CVE-2022-21908", "CVE-2022-21913", "CVE-2022-21914",
                "CVE-2022-21915", "CVE-2022-21916", "CVE-2022-21919", "CVE-2022-21920",
                "CVE-2022-21922", "CVE-2022-21924", "CVE-2022-21925");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-13 11:12:56 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-12 09:31:05 +0530 (Wed, 12 Jan 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5009610)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5009610");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Active Directory Domain Services.

  - An elevation of privilege vulnerability in Virtual Machine IDE Drive.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, disclose sensitive information, conduct remote code execution,
  bypass security restrictions, conduct DoS attacks and conduct spoofing attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5009610");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"advapi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.25827"))
{
  report = report_fixed_ver(file_checked:dllPath + "\advapi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.25827");
  security_message(data:report);
  exit(0);
}
exit(99);
