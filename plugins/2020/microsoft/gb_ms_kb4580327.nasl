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
  script_oid("1.3.6.1.4.1.25623.1.0.817489");
  script_version("2020-10-14T15:29:30+0000");
  script_cve_id("CVE-2020-1147", "CVE-2020-16876", "CVE-2020-16887", "CVE-2020-16889",
                "CVE-2020-16891", "CVE-2020-16892", "CVE-2020-16896", "CVE-2020-16897",
                "CVE-2020-16900", "CVE-2020-16902", "CVE-2020-16905", "CVE-2020-16909",
                "CVE-2020-16910", "CVE-2020-16911", "CVE-2020-16912", "CVE-2020-16914",
                "CVE-2020-16916", "CVE-2020-16919", "CVE-2020-16920", "CVE-2020-16922",
                "CVE-2020-16923", "CVE-2020-16924", "CVE-2020-16927", "CVE-2020-16935",
                "CVE-2020-16936", "CVE-2020-16937", "CVE-2020-16939", "CVE-2020-16940",
                "CVE-2020-16967", "CVE-2020-16968", "CVE-2020-16972", "CVE-2020-16973",
                "CVE-2020-16974", "CVE-2020-16975", "CVE-2020-16976");
  script_tag(name:"cvss_base", value:"9.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-15 11:08:37 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-14 08:49:58 +0530 (Wed, 14 Oct 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4580327)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4580327");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to errors,

  - NetBIOS over TCP (NBT) Extensions (NetBT) improperly handle objects in memory.

  - Windows Network Connections Service improperly handles objects in memory.

  - Windows improperly handles COM object creation.

  - Windows Application Compatibility Client Library improperly handles registry
    operations.

  - Windows kernel fails to properly handle objects in memory.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, conduct DoS condition, bypass security restrictions
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Microsoft Windows 10 for 32-bit/x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4580327");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Urlmon.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.18724"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Urlmon.dll",
                            file_version:fileVer, vulnerable_range:"11.0.10240.0 - 11.0.10240.18724");
  security_message(data:report);
  exit(0);
}
exit(99);
