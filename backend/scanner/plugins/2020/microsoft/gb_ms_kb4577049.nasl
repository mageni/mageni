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
  script_oid("1.3.6.1.4.1.25623.1.0.817362");
  script_version("2020-09-09T16:14:03+0000");
  script_cve_id("CVE-2020-0782", "CVE-2020-0790", "CVE-2020-0838", "CVE-2020-0839",
                "CVE-2020-0875", "CVE-2020-0878", "CVE-2020-0886", "CVE-2020-0911",
                "CVE-2020-0912", "CVE-2020-0914", "CVE-2020-0921", "CVE-2020-0922",
                "CVE-2020-0941", "CVE-2020-0997", "CVE-2020-1012", "CVE-2020-1013",
                "CVE-2020-1030", "CVE-2020-1031", "CVE-2020-1034", "CVE-2020-1038",
                "CVE-2020-1039", "CVE-2020-1052", "CVE-2020-1053", "CVE-2020-1057",
                "CVE-2020-1074", "CVE-2020-1083", "CVE-2020-1091", "CVE-2020-1097",
                "CVE-2020-1115", "CVE-2020-1130", "CVE-2020-1133", "CVE-2020-1152",
                "CVE-2020-1172", "CVE-2020-1180", "CVE-2020-1245", "CVE-2020-1250",
                "CVE-2020-1252", "CVE-2020-1256", "CVE-2020-1285", "CVE-2020-1308",
                "CVE-2020-1376", "CVE-2020-1471", "CVE-2020-1491", "CVE-2020-1508",
                "CVE-2020-1559", "CVE-2020-1589", "CVE-2020-1593", "CVE-2020-1596",
                "CVE-2020-1598", "CVE-2020-16854");
  script_tag(name:"cvss_base", value:"9.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-09-09 16:14:03 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4577049)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4577049");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to errors,

  - when Microsoft Windows CloudExperienceHost fails to check COM objects.

  - in how splwow64.exe handles certain calls.

  - in the way that the dnsrslvr.dll handles objects in memory.

  - when the Windows State Repository Service improperly handles objects in memory.

  - in the way that Microsoft COM for Windows handles objects in memory.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, conduct DoS conditions and
  disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4577049");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.18695"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Upnphost.dll",
                            file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.18695");
  security_message(data:report);
  exit(0);
}
exit(99);
