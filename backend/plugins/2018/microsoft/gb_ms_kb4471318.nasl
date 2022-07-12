###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4471318)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814619");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8477", "CVE-2018-8514", "CVE-2018-8611", "CVE-2018-8619",
                "CVE-2018-8621", "CVE-2018-8622", "CVE-2018-8625", "CVE-2018-8631",
                "CVE-2018-8639", "CVE-2018-8641", "CVE-2018-8643", "CVE-2018-8595",
                "CVE-2018-8596");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-12 13:11:27 +0530 (Wed, 12 Dec 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4471318)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4471318");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Windows kernel improperly handles objects in memory.

  - Internet Explorer VBScript execution policy does not properly
    restrict VBScript under specific conditions.

  - Scripting engine improperly handles objects in memory in Internet
    Explorer.

  - Windows kernel-mode driver fails to properly handle objects in memory.

  - Internet Explorer improperly accesses objects in memory.

  - Windows GDI component improperly discloses the contents of its
    memory.

  - Windows Domain Name System (DNS) servers when they fail to properly handle
    requests.

  - Windows Win32k component fails to properly handle objects in
    memory.

  - VBScript engine improperly handles objects in memory.

  - Remote Procedure Call runtime improperly initializes objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, elevate privileges and obtain information to further
  compromise the user's system.");

  script_tag(name:"affected", value:"Windows Server 2008 R2 for x64-based Systems Service Pack 1

  Windows 7 for 32-bit/x64 Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4471318");
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

if(hotfix_check_sp(win2008r2:2, win7:2, win7x64:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24313"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Win32k.sys",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24313");
  security_message(data:report);
  exit(0);
}
exit(0);
