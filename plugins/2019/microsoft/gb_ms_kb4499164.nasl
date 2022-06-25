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
  script_oid("1.3.6.1.4.1.25623.1.0.815051");
  script_version("2019-05-15T13:58:40+0000");
  script_cve_id("CVE-2018-11091", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130",
                "CVE-2019-0683", "CVE-2019-0708", "CVE-2019-0725", "CVE-2019-0734",
                "CVE-2019-0758", "CVE-2019-0863", "CVE-2019-0881", "CVE-2019-0882",
                "CVE-2019-0884", "CVE-2019-0885", "CVE-2019-0889", "CVE-2019-0890",
                "CVE-2019-0891", "CVE-2019-0893", "CVE-2019-0894", "CVE-2019-0895",
                "CVE-2019-0896", "CVE-2019-0897", "CVE-2019-0898", "CVE-2019-0899",
                "CVE-2019-0900", "CVE-2019-0901", "CVE-2019-0902", "CVE-2019-0903",
                "CVE-2019-0911", "CVE-2019-0918", "CVE-2019-0921", "CVE-2019-0930",
                "CVE-2019-0936", "CVE-2019-0940", "CVE-2019-0961");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-15 13:58:40 +0000 (Wed, 15 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-15 10:16:13 +0530 (Wed, 15 May 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4499164)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4499164");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows Graphics Device Interface (GDI) improperly handles objects in the
    memory.

  - Internet Explorer improperly handles URLs.

  - Windows fails to properly handle certain symbolic links.

  - An error Active Directory Forest trusts due to a default setting.

  - Windows Server DHCP service improperly process specially crafted packets.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code on a victim system, obtain information to
  further compromise the user's system, gain elevated privileges, conduct remote
  code execution and conduct spoofing attack.");

  script_tag(name:"affected", value:"Windows 7 for 32-bit/x64 Systems Service Pack 1

  Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4499164");
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

if(version_is_less(version:fileVer, test_version:"6.1.7601.24441"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntdll.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24441");
  security_message(data:report);
  exit(0);
}
exit(99);
