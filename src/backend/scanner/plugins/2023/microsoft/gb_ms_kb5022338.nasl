# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.826831");
  script_version("2023-01-12T10:12:15+0000");
  script_cve_id("CVE-2023-21546", "CVE-2023-21543", "CVE-2023-21548", "CVE-2023-21555",
                "CVE-2023-21556", "CVE-2023-21561", "CVE-2023-21679", "CVE-2023-21730",
                "CVE-2023-21527", "CVE-2023-21532", "CVE-2023-21537", "CVE-2023-21541",
                "CVE-2023-21542", "CVE-2023-21549", "CVE-2023-21552", "CVE-2023-21557",
                "CVE-2023-21560", "CVE-2023-21563", "CVE-2023-21675", "CVE-2023-21678",
                "CVE-2023-21680", "CVE-2023-21681", "CVE-2023-21682", "CVE-2023-21726",
                "CVE-2023-21728", "CVE-2023-21732", "CVE-2023-21746", "CVE-2023-21748",
                "CVE-2023-21750", "CVE-2023-21757", "CVE-2023-21774", "CVE-2023-21525",
                "CVE-2023-21765", "CVE-2023-21752", "CVE-2023-21776", "CVE-2023-21749",
                "CVE-2023-21772", "CVE-2023-21524", "CVE-2023-21747", "CVE-2023-21773",
                "CVE-2023-21754", "CVE-2023-21760");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 10:00:19 +0530 (Wed, 11 Jan 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5022338)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5022338");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution Vulnerability in Windows Layer 2 Tunneling Protocol.

  - An elevation of privilege vulnerability in Windows Kernel.

  - A Denial of Service Vulnerability in Windows Layer 2 Tunneling Protocol.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit Systems  Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/50122338");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.26321"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.26321");
  security_message(data:report);
  exit(0);
}
exit(99);
