###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft VBScript Scripting Engine Remote Code Execution Vulnerability (980232)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-18
#       - To detect file version 'VBScript.dll' on vista, win 2008 and win 7
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
  script_oid("1.3.6.1.4.1.25623.1.0.902159");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0483");
  script_bugtraq_id(38463);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Microsoft VBScript Scripting Engine Remote Code Execution Vulnerability (980232)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023668.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/981169.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-022.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page.");
  script_tag(name:"affected", value:"Microsoft Windows 7

  Microsoft Windows 2000 Service Pack 4 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2003 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 1/2 and prior.

  Microsoft Windows Server 2008 Service Pack 1/2 and prior.");
  script_tag(name:"insight", value:"The flaw exists in the way 'VBScript' interacts with Windows Help files
  when using Internet Explorer. If a malicious Web site displayed a specially
  crafted dialog box and a user pressed the F1 key, it allows arbitrary code
  to be executed in the security context of the currently logged-on user.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-022.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

if((hotfix_missing(name:"981349") == 0) || (hotfix_missing(name:"981350") == 0) ||
   (hotfix_missing(name:"981332")==0)) {
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Vbscript.dll");
  if(!sysVer){
    exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_in_range(version:sysVer, test_version:"5.6", test_version2:"5.6.0.8837") ||
     version_in_range(version:sysVer, test_version:"5.7", test_version2:"5.7.6002.22353")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.6.0.8838")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.7.6002.22354") ||
       version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.22999")){

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
    if(version_is_less(version:sysVer, test_version:"5.6.0.8838") ||
       version_in_range(version:sysVer, test_version:"5.7", test_version2:"5.7.6002.22353") ||
       version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.22999")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Vbscript.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.6002.18221") ||
     version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.18908")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
     exit(0);
}

if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.8.7600.16546")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

