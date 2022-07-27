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
  script_oid("1.3.6.1.4.1.25623.1.0.818859");
  script_version("2021-11-12T03:03:36+0000");
  script_cve_id("CVE-2021-38631", "CVE-2021-38665", "CVE-2021-38666", "CVE-2021-41356",
                "CVE-2021-41366", "CVE-2021-41367", "CVE-2021-41370", "CVE-2021-41371",
                "CVE-2021-41377", "CVE-2021-41379", "CVE-2021-42275", "CVE-2021-42276",
                "CVE-2021-42277", "CVE-2021-42279", "CVE-2021-42283", "CVE-2021-42284",
                "CVE-2021-42285");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-10 16:38:00 +0000 (Wed, 10 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-10 10:57:04 +0530 (Wed, 10 Nov 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5007207)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5007207");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An information disclosure vulnerability in Windows Remote Desktop Protocol (RDP).

  - An elevation of privilege vulnerability in Credential Security Support Provider Protocol (CredSSP).

  - Remote code execution vulnerability in Microsoft COM for Windows.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information, perform remote code execution, cause
  denial of service condition and elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5007207");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"drivers\fastfat.sys");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.19118"))
{
  report = report_fixed_ver(file_checked:dllPath + "\drivers\Fastfat.sys",
                            file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.19118");
  security_message(data:report);
  exit(0);
}
exit(99);
