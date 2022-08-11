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
  script_oid("1.3.6.1.4.1.25623.1.0.818141");
  script_version("2021-06-15T03:25:17+0000");
  script_cve_id("CVE-2021-1675", "CVE-2021-26414", "CVE-2021-31199", "CVE-2021-31201",
                "CVE-2021-31953", "CVE-2021-31954", "CVE-2021-31956", "CVE-2021-31958",
                "CVE-2021-31959", "CVE-2021-31962", "CVE-2021-31968", "CVE-2021-31970",
                "CVE-2021-31971", "CVE-2021-31972", "CVE-2021-31973", "CVE-2021-31974",
                "CVE-2021-31975", "CVE-2021-31976", "CVE-2021-31977", "CVE-2021-33742");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-06-15 10:41:11 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-10 10:54:39 +0530 (Thu, 10 Jun 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5003638)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5003638");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A memory corruption error in Scripting Engine.

  - An error in Windows Hyper-V.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform remote code execution, conduct spoofing attacks, disclose sensitive
  information and bypass security restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32-bit Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5003638");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Pcadm.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.4466"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Pcadm.dll",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.4466");
  security_message(data:report);
  exit(0);
}
exit(99);
