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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815052");
  script_version("2019-05-15T13:58:40+0000");
  script_cve_id("CVE-2018-11091", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130",
                "CVE-2019-0683", "CVE-2019-0707", "CVE-2019-0725", "CVE-2019-0734",
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
  script_tag(name:"creation_date", value:"2019-05-15 10:50:54 +0530 (Wed, 15 May 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4499151)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4499151");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - Scripting engine improperly handles objects in memory in Microsoft browsers.

  - Windows Error Reporting (WER) improperly handles files.

  - Microsoft Windows OLE fails to properly validate user input.

  - An error in Microsoft Windows when a man-in-the-middle attacker is able to
    successfully decode and replace authentication request using Kerberos.

  - Windows Kernel improperly handles key enumeration.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows GDI component improperly discloses the contents of its memory.

  - Speculative execution side channel vulnerabilities known as Microarchitectural
    Data Sampling.

  - Microsoft browsers improperly access objects in memory.

  - Internet Explorer improperly handles URLs and objects in memory.

  - An error in the Network Driver Interface Specification (NDIS).

  - Windows fails to properly handle certain symbolic links.

  - Windows Server DHCP service improperly process specially crafted packets.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to elevate privileges, execute arbitrary code, read unauthorized
  information and take control of the affected system.");

  script_tag(name:"affected", value:"Windows 8.1 for 32-bit/x64,

  Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4499151");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"inetcomm.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.19355"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Inetcomm.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19355");
  security_message(data:report);
  exit(0);
}
exit(99);
