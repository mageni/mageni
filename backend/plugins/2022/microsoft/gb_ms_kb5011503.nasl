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
  script_oid("1.3.6.1.4.1.25623.1.0.818976");
  script_version("2022-03-10T05:08:03+0000");
  script_cve_id("CVE-2022-21967", "CVE-2022-21975", "CVE-2022-21977", "CVE-2022-21990",
                "CVE-2022-22010", "CVE-2022-23253", "CVE-2022-23278", "CVE-2022-23281",
                "CVE-2022-23283", "CVE-2022-23284", "CVE-2022-23285", "CVE-2022-23286",
                "CVE-2022-23287", "CVE-2022-23288", "CVE-2022-23290", "CVE-2022-23291",
                "CVE-2022-23293", "CVE-2022-23294", "CVE-2022-23296", "CVE-2022-23297",
                "CVE-2022-23298", "CVE-2022-23299", "CVE-2022-24454", "CVE-2022-24455",
                "CVE-2022-24459", "CVE-2022-24460", "CVE-2022-24502", "CVE-2022-24503",
                "CVE-2022-24505", "CVE-2022-24507");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-10 11:17:35 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-09 06:00:50 +0530 (Wed, 09 Mar 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5011503)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5011503");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Fax and Scan Service.

  - An elevation of privilege vulnerability in Windows ALPC.

  - An elevation of privilege vulnerability in Windows Print Spooler .

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, disclose sensitive information, conduct remote code execution,
  bypass security restrictions, conduct spoofing and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5011503");
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.2685"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.2685");
  security_message(data:report);
  exit(0);
}
exit(99);
