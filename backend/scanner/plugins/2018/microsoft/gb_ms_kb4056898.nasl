###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4056898)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812386");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754", "CVE-2018-0744",
                "CVE-2018-0753", "CVE-2018-0754", "CVE-2018-0788", "CVE-2018-0752",
                "CVE-2018-0751", "CVE-2018-0749", "CVE-2018-0747", "CVE-2018-0748",
                "CVE-2018-0746");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-01-04 16:27:57 +0530 (Thu, 04 Jan 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4056898)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4056898");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple errors in Windows Adobe Type Manager Font Driver (ATMFD.dll) when
    it fails to properly handle objects in memory.

  - An error in the way that Windows handles objects in memory.

  - Multiple errors in the way that the Windows Kernel API enforces permissions.

  - An error in the Microsoft Server Message Block (SMB) Server when an attacker
    with valid credentials attempts to open a specially crafted file over the SMB
    protocol on the same machine.

  - Multiple errors in the Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space Layout Randomization
    (ASLR) bypass.

  - Multiple errors leading to 'speculative execution side-channel attacks' that
    affect many modern processors and operating systems including Intel, AMD, and ARM.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and take control of an affected system, gain access to
  sensitive data, cause a target system to stop responding, impersonate processes,
  interject cross-process communication, interrupt system functionality, bypass
  certain security checks and conduct bounds check bypass, branch target injection,
  rogue data cache load.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4056898");

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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.18895"))
{
  report = report_fixed_ver( file_checked:sysPath + "\Ntoskrnl.exe",
                             file_version:fileVer, vulnerable_range:"Less than 6.3.9600.18895" );
  security_message(data:report);
  exit(0);
}
exit(0);
