###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4457131)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814013");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8446", "CVE-2018-8447", "CVE-2018-8449", "CVE-2018-8452",
                "CVE-2018-0965", "CVE-2018-8271", "CVE-2018-8315", "CVE-2018-8332",
                "CVE-2018-8335", "CVE-2018-8354", "CVE-2018-8367", "CVE-2018-8392",
                "CVE-2018-8393", "CVE-2018-8410", "CVE-2018-8419", "CVE-2018-8420",
                "CVE-2018-8421", "CVE-2018-8424", "CVE-2018-8425", "CVE-2018-8433",
                "CVE-2018-8434", "CVE-2018-8435", "CVE-2018-8438", "CVE-2018-8439",
                "CVE-2018-8440", "CVE-2018-8442", "CVE-2018-8443", "CVE-2018-8455",
                "CVE-2018-8457", "CVE-2018-8462", "CVE-2018-8464", "CVE-2018-8465",
                "CVE-2018-8466", "CVE-2018-8467", "CVE-2018-8468", "CVE-2018-8469",
                "CVE-2018-8470", "CVE-2018-8475", "CVE-2018-5391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-12 12:06:44 +0530 (Wed, 12 Sep 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4457131)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4457131");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - Microsoft Edge PDF Reader improperly handles objects in memory.

  - DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects in memory.

  - Microsoft XML Core Services MSXML parser processes user input.

  - Windows improperly parses files.

  - Windows kernel improperly handles objects in memory.

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Microsoft JET Database Engine improperly handles objects in memory.

  - Windows Graphics component improperly handles objects in memory.

  - Windows Hyper-V BIOS loader fails to provide a high-entropy source.

  - Windows kernel fails to properly initialize a memory address.

  - Windows does not properly handle specially crafted image files.

  - Scripting engine does not properly handle objects in memory in Microsoft
    browsers.

  - A universal cross-site scripting (UXSS) condition in Internet Explorer.

  - Microsoft Server Block Message (SMB) improperly handles crafted requests
    to the server.

  - Denial of service vulnerability (named FragmentSmack).

  - Windows font library improperly handles specially crafted embedded fonts.

  - Device Guard incorrectly validates an untrusted file.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - Windows GDI component improperly discloses the contents of its memory.

  - Microsoft Edge improperly handles specific HTML content.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to crash the affected system, execute arbitrary code on the host operating system,
  disclose contents of System memory and also read privileged data across trust
  boundaries.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1607 x32/x64

  Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4457131");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.2484"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.14393.0 - 11.0.14393.2484");
  security_message(data:report);
  exit(0);
}
exit(99);
