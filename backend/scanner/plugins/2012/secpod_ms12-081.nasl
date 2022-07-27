###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows File Handling Component Remote Code Execution Vulnerability (2758857)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901304");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-4774");
  script_bugtraq_id(56443);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-12-12 09:40:29 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Windows File Handling Component Remote Code Execution Vulnerability (2758857)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51493/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2758857");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms12-081.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to gain the same user rights as
  the current user by execute arbitrary code with system-level privileges.");
  script_tag(name:"affected", value:"Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to error in the File Handling component, which allow user
  browses to a folder that contains a file or sub folder names and can be
  exploited to corrupt memory via a file with a specially crafted filename.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-081.");
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

kernelPath = smb_get_systemroot();
if(!kernelPath){
  exit(0);
}

kernelVer = fetch_file_version(sysPath:kernelPath, file_name:"system32\Kernel32.dll");

if(!kernelVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:kernelVer, test_version:"5.1.2600.6293")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  if(version_is_less(version:kernelVer, test_version:"5.2.3790.5069")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## and 6.0.6002.22000 before 6.0.6002.22942 (LDR)
  if(version_is_less(version:kernelVer, test_version:"6.0.6002.18704") ||
     version_in_range(version:kernelVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22941")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## before 6.1.7600.17135 and 6.1.7600.22000 before 6.1.7600.21335 (RTM)
  ## before 6.1.7601.17965 and 6.1.7601.21000 before 6.1.7601.22125 (SP1)
  if(version_is_less(version:kernelVer, test_version:"6.1.7600.17135") ||
     version_in_range(version:kernelVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21334")||
     version_in_range(version:kernelVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17964")||
     version_in_range(version:kernelVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22124")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
