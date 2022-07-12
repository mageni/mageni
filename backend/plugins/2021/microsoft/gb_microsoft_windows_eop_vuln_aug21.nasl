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
  script_oid("1.3.6.1.4.1.25623.1.0.818842");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2021-36934");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-30 18:29:00 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-10-26 00:16:17 +0530 (Tue, 26 Oct 2021)");
  script_name("Microsoft Windows Elevation of Privilege Vulnerability (HiveNightmare, SeriousSAM)");

  script_tag(name:"summary", value:"Microsoft Windows is prone to an elevation of privilege
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because of overly permissive Access Control
  Lists (ACLs) on multiple system files, including the Security Accounts Manager (SAM) database.

  The flaw is dubbed 'HiveNightmare' or 'SeriousSAM'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker who successfully
  exploited this vulnerability to run arbitrary code with SYSTEM privileges. An attacker could
  then install programs, view, change, or delete data, or create new accounts with full user
  rights.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems

  - Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.

  After installing this security update, you must manually delete all shadow copies of system files,
  including the SAM database, to fully mitigate this vulnerability. Simply installing this security
  update will not fully mitigate this vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/topic/august-10-2021-kb5005030-os-build-17763-2114-cec503ed-cc09-4641-bdc1-988153e0bd9a");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/topic/august-10-2021-kb5005031-os-build-18363-1734-8af726da-a39b-417d-a5fb-670c42d69e78");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/506989");
  script_xref(name:"URL", value:"https://support.microsoft.com/topic/1ceaa637-aaa3-4b58-a48b-baf72a2fa9e7");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

if(!dllPath = smb_get_system32root())
  exit(0);

if(!fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe"))
  exit(0);

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.2113")) {
  vulnerable_range = "10.0.17763.0 - 10.0.17763.2113";
}

else if(version_in_range(version:fileVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.1733")) {
  vulnerable_range = "10.0.18362.0 - 10.0.18362.1733";
}

if(vulnerable_range) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:vulnerable_range);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);