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
  script_oid("1.3.6.1.4.1.25623.1.0.821271");
  script_version("2022-07-14T06:04:04+0000");
  script_cve_id("CVE-2022-21845", "CVE-2022-22022", "CVE-2022-22023", "CVE-2022-22024",
                "CVE-2022-22025", "CVE-2022-22026", "CVE-2022-22027", "CVE-2022-22028",
                "CVE-2022-22029", "CVE-2022-22031", "CVE-2022-22034", "CVE-2022-22036",
                "CVE-2022-22037", "CVE-2022-22038", "CVE-2022-22039", "CVE-2022-22040",
                "CVE-2022-22041", "CVE-2022-22042", "CVE-2022-22043", "CVE-2022-22045",
                "CVE-2022-22047", "CVE-2022-22048", "CVE-2022-22049", "CVE-2022-22050",
                "CVE-2022-22711", "CVE-2022-27776", "CVE-2022-30202", "CVE-2022-30203",
                "CVE-2022-30205", "CVE-2022-30206", "CVE-2022-30208", "CVE-2022-30209",
                "CVE-2022-30211", "CVE-2022-30212", "CVE-2022-30213", "CVE-2022-30214",
                "CVE-2022-30215", "CVE-2022-30220", "CVE-2022-30221", "CVE-2022-30222",
                "CVE-2022-30223", "CVE-2022-30224", "CVE-2022-30225", "CVE-2022-30226");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-14 06:04:04 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-14 17:53:00 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 09:46:45 +0530 (Wed, 13 Jul 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5015811)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5015811");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Fax Service.

  - A security bypass vulnerability in BitLocker.

  - An insufficiently protected credentials vulnerability might leak
    authentication or cookie header data.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions and cause a denial of service condition on an
  affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5015811");
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.3164"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.3164");
  security_message(data:report);
  exit(0);
}
exit(99);
