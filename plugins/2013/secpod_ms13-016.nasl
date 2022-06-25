###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2778344)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902943");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-1248", "CVE-2013-1249", "CVE-2013-1250", "CVE-2013-1264",
                "CVE-2013-1251", "CVE-2013-1265", "CVE-2013-1252", "CVE-2013-1266",
                "CVE-2013-1253", "CVE-2013-1267", "CVE-2013-1254", "CVE-2013-1255",
                "CVE-2013-1256", "CVE-2013-1257", "CVE-2013-1258", "CVE-2013-1259",
                "CVE-2013-1260", "CVE-2013-1261", "CVE-2013-1262", "CVE-2013-1263",
                "CVE-2013-1268", "CVE-2013-1269", "CVE-2013-1270", "CVE-2013-1271",
                "CVE-2013-1272", "CVE-2013-1273", "CVE-2013-1274", "CVE-2013-1275",
                "CVE-2013-1276", "CVE-2013-1277");
  script_bugtraq_id(57786, 57791, 57792, 57806, 57793, 57807, 57794, 57808, 57795,
                    57809, 57796, 57797, 57798, 57799, 57800, 57801, 57802, 57803,
                    57804, 57805, 57810, 57811, 57812, 57813, 57814, 57815, 57816,
                    57817, 57818, 57819);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-02-13 06:40:06 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2778344)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2778344");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028124");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-016");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to a specially crafted
  program to exploit race conditions in 'win32k.sys' and gain System level
  privileges.");
  script_tag(name:"affected", value:"Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaws due to an error in 'win32k.sys' when handling kernel-mode driver
  objects in memory.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-016.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}


sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.1.2600.6334")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.2.3790.5106")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18764") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23012")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.17206") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21415")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18042")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22208")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
