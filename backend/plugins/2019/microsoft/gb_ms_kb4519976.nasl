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
  script_oid("1.3.6.1.4.1.25623.1.0.815710");
  script_version("2019-10-09T12:58:40+0000");
  script_cve_id("CVE-2019-0608", "CVE-2019-1166", "CVE-2019-1192", "CVE-2019-1238",
                "CVE-2019-1315", "CVE-2019-1318", "CVE-2019-1319", "CVE-2019-1325",
                "CVE-2019-1326", "CVE-2019-1333", "CVE-2019-1338", "CVE-2019-1339",
                "CVE-2019-1341", "CVE-2019-1342", "CVE-2019-1344", "CVE-2019-1346",
                "CVE-2019-1357", "CVE-2019-1358", "CVE-2019-1359", "CVE-2019-1361",
                "CVE-2019-1362", "CVE-2019-1363", "CVE-2019-1364", "CVE-2019-1365",
                "CVE-2019-1367", "CVE-2019-1371");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-09 12:58:40 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-09 12:02:34 +0530 (Wed, 09 Oct 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4519976)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4519976");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper parsing of HTTP content.

  - Improper handling of objects in memory in VBScript engine.

  - Improperly handling of hard links in Windows Error Reporting manager.

  - Improper handling of a Registry Restore Key function in 'umpo.dll' of
    Power Service.

  - Improper handling of process crash in Windows Error Reporting manager.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code on a victim system, obtain information
  to further compromise the user's system, gain elevated privileges and disclose
  sensitive information or cause denial of service.");

  script_tag(name:"affected", value:"Windows 7 for 32-bit/x64 Systems Service Pack 1

  Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4519976");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Mshtml.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.19507"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Mshtml.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.19507");
  security_message(data:report);
  exit(0);
}
exit(99);
