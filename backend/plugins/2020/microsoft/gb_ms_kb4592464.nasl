# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817549");
  script_version("2020-12-09T14:20:17+0000");
  script_cve_id("CVE-2020-16958", "CVE-2020-16959", "CVE-2020-16960", "CVE-2020-16961",
                "CVE-2020-16962", "CVE-2020-16963", "CVE-2020-16964", "CVE-2020-17092",
                "CVE-2020-17096", "CVE-2020-17097", "CVE-2020-17098", "CVE-2020-17099",
                "CVE-2020-17140");
  script_tag(name:"cvss_base", value:"9.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-09 14:20:17 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-09 10:50:46 +0530 (Wed, 09 Dec 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4592464)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4592464");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in the Backup Engine allows a local authenticated malicious
    user to gain elevated privileges on the system.

  - An error in the GDI+ component.

  - An error in the SMBv2 component.
  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privilges and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4592464");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Ntoskrnl.exe");
if(!dllVer)
  exit(0);

if(version_is_less(version:dllVer, test_version:"10.0.10240.18782"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Ntoskrnl.exe",
                            file_version:dllVer, vulnerable_range:"Less than 10.0.10240.18782");
  security_message(data:report);
  exit(0);
}
exit(99);
