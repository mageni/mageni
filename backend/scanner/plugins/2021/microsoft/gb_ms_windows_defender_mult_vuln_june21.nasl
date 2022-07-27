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
  script_oid("1.3.6.1.4.1.25623.1.0.818323");
  script_version("2021-06-15T08:02:31+0000");
  script_cve_id("CVE-2021-31985", "CVE-2021-31978");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-15 10:41:11 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-10 10:10:36 +0530 (Thu, 10 Jun 2021)");
  script_name("Microsoft Windows Defender Multiple Vulnerabilities - June21");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates released for Microsoft Windows
  Defender Protection Engine dated 08-06-2021.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in
  Microsoft Windows Defender");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows Defender on Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31985");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31978");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1,win2012:1, win2012R2:1,
                   win10:1, win10x64:1, win2016:1, win2008:3, win2019:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath) {
  exit(0);
}

mpsigstubVer = fetch_file_version(sysPath:sysPath, file_name:"mpsigstub.exe");
if(!mpsigstubVer) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows Defender";
if(!registry_key_exists(key:key)){
  exit(0);
}

def_version = registry_get_sz(key:"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
                              item:"EngineVersion");
if(!def_version){
  exit(0);
}

##First version of the Microsoft Malware Protection Engine with this vulnerability addressed: Version 1.1.18200.3
if(version_is_less(version:def_version, test_version:"1.1.18200.3"))
{
  report = report_fixed_ver(installed_version:def_version, fixed_version: "1.1.18200.3 or higher");
  security_message(data:report);
  exit(0);
}
exit(0);
