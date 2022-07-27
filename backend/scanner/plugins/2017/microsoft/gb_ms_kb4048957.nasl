###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4048957)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812149");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-11869", "CVE-2017-11768", "CVE-2017-11788", "CVE-2017-11880",
                "CVE-2017-11791", "CVE-2017-11827", "CVE-2017-11834", "CVE-2017-11835",
                "CVE-2017-11837", "CVE-2017-11838", "CVE-2017-11843", "CVE-2017-11846",
                "CVE-2017-11847", "CVE-2017-11848", "CVE-2017-11849", "CVE-2017-11851",
                "CVE-2017-11852", "CVE-2017-11853", "CVE-2017-11855", "CVE-2017-11856",
                "CVE-2017-11858", "CVE-2017-11831", "CVE-2017-11832");
  script_bugtraq_id(101742, 101705, 101711, 101755, 101715, 101703, 101725, 101736,
		            101722, 101737, 101740, 101741, 101729, 101709, 101762, 101763,
		            101739, 101764, 101751, 101753, 101716, 101721, 101726);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-15 13:39:48 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4048957)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4048957");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - This security update includes improvements and resolves the following issues:
    Addressed issue where applications based on the Microsoft JET Database Engine
    (Microsoft Access 2007 and older or non-Microsoft applications) fail when
    creating or opening Microsoft Excel .xls files.

  - Security updates to Microsoft Windows Search Component, Microsoft Graphics
    Component, Windows kernel-mode drivers, Windows Media Player, and Windows kernel.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read data that was not intended to be disclosed, and obtain information to
  further compromise the user's system.");

  script_tag(name:"affected", value:"Windows Server 2008 R2 for x64-based Systems Service Pack 1

  Windows 7 for 32-bit/x64 Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4048957");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"advapi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.23915"))
{
  report = report_fixed_ver(file_checked:sysPath + "\advapi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.23915");
  security_message(data:report);
  exit(0);
}
exit(0);
