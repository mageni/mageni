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
  script_oid("1.3.6.1.4.1.25623.1.0.815024");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2019-0685", "CVE-2019-0688", "CVE-2019-0730", "CVE-2019-0848",
                "CVE-2019-0849", "CVE-2019-0851", "CVE-2019-0731", "CVE-2019-0732",
                "CVE-2019-0735", "CVE-2019-0853", "CVE-2019-0856", "CVE-2019-0739",
                "CVE-2019-0752", "CVE-2019-0753", "CVE-2019-0764", "CVE-2019-0859",
                "CVE-2019-0860", "CVE-2019-0861", "CVE-2019-0862", "CVE-2019-0790",
                "CVE-2019-0791", "CVE-2019-0877", "CVE-2019-0879", "CVE-2019-0792",
                "CVE-2019-0793", "CVE-2019-0794", "CVE-2019-0795", "CVE-2019-0796",
                "CVE-2019-0806", "CVE-2019-0810", "CVE-2019-0812", "CVE-2019-0814",
                "CVE-2019-0829", "CVE-2019-0835", "CVE-2019-0836", "CVE-2019-0838",
                "CVE-2019-0839", "CVE-2019-0842", "CVE-2019-0844", "CVE-2019-0845",
                "CVE-2019-0846", "CVE-2019-0847", "CVE-2019-0802", "CVE-2019-0803",
                "CVE-2019-0805", "CVE-2019-0671", "CVE-2019-0673", "CVE-2019-0674");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-10 10:03:26 +0530 (Wed, 10 Apr 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4493470)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4493470");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The scripting engine improperly handles objects in memory in Microsoft Edge.

  - The IOleCvt interface improperly renders ASP webpage content.

  - The scripting engine improperly handles objects in memory in Internet Explorer.

  - Windows improperly handles calls to the LUAFV driver.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows Client Server Run-Time Subsystem (CSRSS) fails to properly handle
    objects in memory.

  - Microsoft XML Core Services MSXML parser improperly processes user input.

  - OLE automation improperly handles objects in memory.

  - Windows Task Scheduler improperly discloses credentials to Windows Credential
    Manager.

  - Terminal Services component improperly discloses the contents of its memory.

  - The Win32k component fails to properly handle objects in memory.

  - The win32k component improperly provides kernel information.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows improperly handles objects in memory.

  - Microsoft browsers do not properly validate input under specific conditions.

  - Windows TCP/IP stack improperly handles fragmented IP packets.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, disclose sensitive information, bypass security
  restrictions and compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1607 x32/x64

  Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4493470");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
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

if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.2905"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.14393.0 - 11.0.14393.2905");
  security_message(data:report);
  exit(0);
}
exit(99);
