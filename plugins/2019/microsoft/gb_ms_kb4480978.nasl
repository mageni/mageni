###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4480978)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814644");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2019-0536", "CVE-2019-0538", "CVE-2019-0539", "CVE-2019-0541",
                "CVE-2019-0543", "CVE-2019-0545", "CVE-2019-0551", "CVE-2019-0552",
                "CVE-2019-0553", "CVE-2019-0554", "CVE-2019-0555", "CVE-2019-0566",
                "CVE-2019-0567", "CVE-2019-0569", "CVE-2019-0570", "CVE-2019-0571",
                "CVE-2019-0572", "CVE-2019-0573", "CVE-2019-0574", "CVE-2019-0575",
                "CVE-2019-0576", "CVE-2019-0577", "CVE-2019-0578", "CVE-2019-0579",
                "CVE-2019-0580", "CVE-2019-0581", "CVE-2019-0582", "CVE-2019-0583",
                "CVE-2019-0584", "CVE-2019-0549");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-09 10:41:16 +0530 (Wed, 09 Jan 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4480978)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4480978");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Windows kernel improperly handles objects in memory.

  - An error in the Microsoft XmlDocument class that could allow an attacker to
    escape from the AppContainer sandbox in the browser.

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - MSHTML engine improperly validates input.

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Windows improperly handles authentication requests.

  - Windows Subsystem for Linux improperly handles objects in memory.

  - Windows Data Sharing Service improperly handles file operations.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows Runtime improperly handles objects in memory.

  - An elevation of privilege exists in Windows COM Desktop Broker.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, gain elevated
  privileges on an affected system and execute arbitrary code in the context of
  the current user.");

  script_tag(name:"affected", value:"Windows 10 Version 1709 for 32-bit Systems

  Windows 10 Version 1709 for 64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4480978");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.16299.0", test_version2:"11.0.16299.636"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.16299.0 - 11.0.16299.636");
  security_message(data:report);
  exit(0);
}
exit(99);
