###############################################################################
# OpenVAS Vulnerability Test
#
# Windows ClickOnce Application Installer Remote Code Execution Vulnerability (2584146)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902657");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0013");
  script_bugtraq_id(51284);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-01-11 09:53:59 +0530 (Wed, 11 Jan 2012)");
  script_name("Windows ClickOnce Application Installer Remote Code Execution Vulnerability (2584146)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47480");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2584146");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-005");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to run arbitrary code
  and take complete control of an affected system. An attacker can gain administrative rights.");

  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior.

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2003 Service Pack 2 and prior.

  Microsoft Windows Vista Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error within the Windows Packager when
  loading ClickOnce applications embedded in Microsoft Office files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-005.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS12-005 Hotfix (2584146)
if(hotfix_missing(name:"2584146") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Packager.exe");
if( sysVer != NULL)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 3" >< SP)
    {
      ##File Information is not available, so taken after applying patch
      if(version_is_less(version:sysVer, test_version:"5.1.2600.6176")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }

  else if(hotfix_check_sp(win2003:3) > 0)
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:sysVer, test_version:"5.2.3790.4936")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Packager.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18542")||
       version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22742")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16917") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21093")||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17726")||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21862")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
