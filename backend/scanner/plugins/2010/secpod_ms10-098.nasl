###############################################################################
# OpenVAS Vulnerability Test
#
# Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2436673)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902275");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_cve_id("CVE-2010-3939", "CVE-2010-3940", "CVE-2010-3941", "CVE-2010-3942",
                "CVE-2010-3943", "CVE-2010-3944");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2436673)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2436673");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS10-098.mspx");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to run arbitrary
  code in the kernel mode.");

  script_tag(name:"affected", value:"Microsoft Windows 7

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2K3 Service Pack 2 and prior.

  Microsoft Windows Vista Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.");

  script_tag(name:"insight", value:"The flaws are due to the way windows kernel-mode driver,

  - improperly allocate memory when copying data from user mode

  - frees objects that are no longer in use

  - manage kernel-mode driver objects

  - validate input passed from user mode.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-098.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

if(hotfix_missing(name:"2436673") == 0){
  exit(0);
}

file_name = "Win32k.sys";
sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:file_name);
  if(sysVer)
  {
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"5.1.2600.6046")){
          report = report_fixed_ver(installed_version:sysVer, file_checked:sysPath + file_name, vulnerable_range:"< 5.1.2600.6046");
          security_message(port:0, data:report);
        }
        exit(0);
      }
      security_message(port:0, data:"The target host was found to be vulnerable because it doesn't have Windows XP Service Pack 3 installed.");
    }
    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4788")){
          report = report_fixed_ver(installed_version:sysVer, file_checked:sysPath + file_name, vulnerable_range:"< 5.2.3790.4788");
          security_message(port:0, data:report);
        }
        exit(0);
      }
      security_message(port:0, data:"The target host was found to be vulnerable because it doesn't have Windows 2003 Service Pack 2 installed.");
    }
  }
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:file_name);
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18539")){
      report = report_fixed_ver(installed_version:sysVer, file_checked:sysPath + file_name, vulnerable_range:"< 6.0.6001.18539");
      security_message(port:0, data:report);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18328")){
      report = report_fixed_ver(installed_version:sysVer, file_checked:sysPath + file_name, vulnerable_range:"< 6.0.6002.18328");
      security_message(port:0, data:report);
    }
    exit(0);
  }
  security_message(port:0, data:"The target host was found to be vulnerable because it doesn't have Windows 2008 Service Pack 1 or 2 installed.");
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16691")){
    report = report_fixed_ver(installed_version:sysVer, file_checked:sysPath + file_name, vulnerable_range:"< 6.1.7600.16691");
    security_message(port:0, data:report);
  }
}

exit(99);