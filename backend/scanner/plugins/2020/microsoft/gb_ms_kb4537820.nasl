# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815776");
  script_version("2020-02-12T15:13:02+0000");
  script_cve_id("CVE-2020-0655", "CVE-2020-0657", "CVE-2020-0658", "CVE-2020-0662",
                "CVE-2020-0665", "CVE-2020-0666", "CVE-2020-0667", "CVE-2020-0668",
                "CVE-2020-0673", "CVE-2020-0674", "CVE-2020-0675", "CVE-2020-0676",
                "CVE-2020-0677", "CVE-2020-0678", "CVE-2020-0680", "CVE-2020-0681",
                "CVE-2020-0682", "CVE-2020-0683", "CVE-2020-0686", "CVE-2020-0691",
                "CVE-2020-0698", "CVE-2020-0703", "CVE-2020-0705", "CVE-2020-0708",
                "CVE-2020-0715", "CVE-2020-0719", "CVE-2020-0720", "CVE-2020-0721",
                "CVE-2020-0722", "CVE-2020-0723", "CVE-2020-0724", "CVE-2020-0725",
                "CVE-2020-0726", "CVE-2020-0729", "CVE-2020-0730", "CVE-2020-0731",
                "CVE-2020-0734", "CVE-2020-0735", "CVE-2020-0736", "CVE-2020-0737",
                "CVE-2020-0738", "CVE-2020-0744", "CVE-2020-0745", "CVE-2020-0748",
                "CVE-2020-0752", "CVE-2020-0753", "CVE-2020-0754", "CVE-2020-0755",
                "CVE-2020-0756");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-12 15:13:02 +0000 (Wed, 12 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-12 12:58:03 +0530 (Wed, 12 Feb 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4537820)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4537820");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - Windows Common Log File System (CLFS) driver fails to properly handle objects
    in memory.

  - Windows Search Indexer improperly handles objects in memory.

  - Cryptography Next Generation (CNG) service improperly handles objects in memory.

  - Windows Error Reporting manager improperly handles hard links.

  - Windows Function Discovery Service improperly handles objects in memory.

  For more information refer the references.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, elevate privilges and disclose sensitive information");

  script_tag(name:"affected", value:"Windows 7 for 32-bit/x64 Systems Service Pack 1

  Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4537820");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24548"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Win32k.sys",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24548");
  security_message(data:report);
  exit(0);
}
exit(99);
