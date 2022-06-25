###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows 'Win32k.sys' Multiple Vulnerabilities (KB4019204)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811028");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0245", "CVE-2017-0246", "CVE-2017-0263", "CVE-2017-8552");
  script_bugtraq_id(98115, 98108);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-05-10 10:30:09 +0530 (Wed, 10 May 2017)");
  script_name("Microsoft Windows 'Win32k.sys' Multiple Vulnerabilities (KB4019204)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft security update KB4019204.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error when the win32k component improperly provides kernel information.

  - An error when Windows improperly handles objects in memory.

  - An error in Windows when the Windows kernel-mode driver fails to properly
    handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode allowing attacker to install programs,
  view, change, or delete data, or create new accounts with full user rights.Also
  an attacker who successfully exploited this vulnerability could run processes
  in an elevated context and can lead to denial of service condition as well.This
  vulnerability also could allow attacker obtain sensitive information to further
  compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows XP SP2 x64

  Microsoft Windows XP SP3 x86

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019204");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0245");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0246");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0263");

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

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win2008:3, winVistax64:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

winVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!winVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:winVer, test_version:"6.0.6002.19778"))
  {
    Vulnerable_range = "Less than 6.0.6002.19778";
    VULN = TRUE ;
  }

  else if(version_in_range(version:winVer, test_version:"6.0.6002.24000", test_version2:"6.0.6002.24094"))
  {
    Vulnerable_range = "6.0.6002.24000 - 6.0.6002.24094";
    VULN = TRUE ;
  }

}

else if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:winVer, test_version:"5.1.2600.7258"))
  {
    Vulnerable_range = "Less than 5.1.2600.7258";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  if(version_is_less(version:winVer, test_version:"5.2.3790.6080"))
  {
    Vulnerable_range = "Less than 5.2.3790.6080";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Win32k.sys" + '\n' +
           'File version:     ' + winVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
