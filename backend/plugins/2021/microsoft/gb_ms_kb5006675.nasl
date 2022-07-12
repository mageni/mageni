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
  script_oid("1.3.6.1.4.1.25623.1.0.818811");
  script_version("2021-10-14T03:43:45+0000");
  script_cve_id("CVE-2021-26441", "CVE-2021-26442", "CVE-2021-36953", "CVE-2021-36970",
                "CVE-2021-38662", "CVE-2021-38663", "CVE-2021-40443", "CVE-2021-40449",
                "CVE-2021-40454", "CVE-2021-40455", "CVE-2021-40460", "CVE-2021-40463",
                "CVE-2021-40465", "CVE-2021-40466", "CVE-2021-40467", "CVE-2021-40470",
                "CVE-2021-40476", "CVE-2021-40477", "CVE-2021-40478", "CVE-2021-40488",
                "CVE-2021-40489", "CVE-2021-41331", "CVE-2021-41332", "CVE-2021-41335",
                "CVE-2021-41338", "CVE-2021-41340", "CVE-2021-41342", "CVE-2021-41343",
                "CVE-2021-41345", "CVE-2021-41347");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-14 10:10:07 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 09:32:30 +0530 (Wed, 13 Oct 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5006675)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5006675");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows Installer.

  - An error in Windows Print Spooler.

  - An elevation of privilege vulnerability in Storage Spaces Controller.

  - An elevation of privilege vulnerability in Windows AppX Deployment Service.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information, perform remote code execution, cause
  denial of service condition, conduct spoofing and elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5006675");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"pcadm.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.19085"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Pcadm.dll",
                            file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.19085");
  security_message(data:report);
  exit(0);
}
exit(99);
