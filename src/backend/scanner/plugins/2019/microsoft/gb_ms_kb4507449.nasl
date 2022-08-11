# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.815403");
  script_version("2019-07-10T14:00:44+0000");
  script_cve_id("CVE-2019-0683", "CVE-2019-0887", "CVE-2019-1001", "CVE-2019-1004",
                "CVE-2019-1006", "CVE-2019-1056", "CVE-2019-1059", "CVE-2019-1063",
                "CVE-2019-1071", "CVE-2019-1073", "CVE-2019-1082", "CVE-2019-1085",
                "CVE-2019-1088", "CVE-2019-1089", "CVE-2019-1093", "CVE-2019-1094",
                "CVE-2019-1095", "CVE-2019-1096", "CVE-2019-1097", "CVE-2019-1098",
                "CVE-2019-1099", "CVE-2019-1100", "CVE-2019-1101", "CVE-2019-1102",
                "CVE-2019-1104", "CVE-2019-1108", "CVE-2019-1116", "CVE-2019-1132");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-10 14:00:44 +0000 (Wed, 10 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-10 09:30:27 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4507449)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4507449");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Remote Desktop Services improperly handles clipboard redirection.

  - Scripting Engine improperly handles  objects in memory in Microsoft browsers.

  - Windows Communication Foundation (WCF) and Windows Identity Foundation (WIF),
    allow signing of SAML tokens with arbitrary symmetric keys.

  - Windows GDI component improperly handles objects in memory.

  - An elevation of privilege vulnerability exists in Active Directory Forest
    trusts due to a default setting.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code on a victim system, obtain information to
  further compromise the user's system and gain elevated privileges.");

  script_tag(name:"affected", value:"Windows 7 for 32-bit/x64 Systems Service Pack 1

  Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4507449");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Ntdll.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24499"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntdll.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24499");
  security_message(data:report);
  exit(0);
}
exit(99);
