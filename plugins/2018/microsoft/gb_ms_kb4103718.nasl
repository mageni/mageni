###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4103718)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813336");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-0954", "CVE-2018-0955", "CVE-2018-0959", "CVE-2018-1022",
                "CVE-2018-1025", "CVE-2018-8114", "CVE-2018-8120", "CVE-2018-8122",
                "CVE-2018-8124", "CVE-2018-8127", "CVE-2018-8136", "CVE-2018-8145",
                "CVE-2018-8164", "CVE-2018-8166", "CVE-2018-8167", "CVE-2018-8174",
                "CVE-2018-8178", "CVE-2018-8897", "CVE-2018-0824", "CVE-2017-11927",
                "CVE-2018-0886");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-09 08:12:54 +0530 (Wed, 09 May 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4103718)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4103718");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - Microsoft browsers improperly access objects in memory.

  - The Win32k component fails to properly handle objects in memory.

  - Windows kernel fails to properly handle objects in memory.

  - The VBScript engine improperly handles objects in memory.

  - The scripting engine improperly handles objects in memory in Microsoft browsers.

  - Windows Common Log File System (CLFS) driver improperly handles objects in memory.

  - Chakra improperly discloses the contents of its memory.

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Windows 'its://' protocol handler unnecessarily sends traffic to a remote site
    in order to determine the zone of a provided URL.

  - An error in Credential Security Support Provider protocol (CredSSP).");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to gain the same user rights as the current user, run arbitrary
  code, disclose sensitive information and run processes in an elevated context
  and it may lead to further compromise of the system.");

  script_tag(name:"affected", value:"Windows 7 for 32-bit/x64 Systems Service Pack 1

  Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4103718");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"advapi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24117"))
{
  report = report_fixed_ver(file_checked:sysPath + "\advapi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24117");
  security_message(data:report);
  exit(0);
}
exit(99);
