###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft JScript Scripting Engine Remote Code Execution Vulnerability (971961)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Added JScript 5.7 on Microsoft Windows 2000 Service Pack 4 (KB975542)
# - By Nikita MR <rnikita@secpod.com> on 2009-11-13
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-29
#     - To detect file version 'JScript.dll' on vista and win 2008
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900929");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1920");
  script_bugtraq_id(36224);
  script_name("Microsoft JScript Scripting Engine Remote Code Execution Vulnerability (971961)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36551/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2563");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-045.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could lead to memory corruption via specially crafted
  web pages and may allow execution of arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Windows 2k  Service Pack 4 and prior
  Microsoft Windows XP  Service Pack 3 and prior
  Microsoft Windows 2k3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.");
  script_tag(name:"insight", value:"The JScript scripting engine does not properly load decoded scripts into
  memory before execution.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-045.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-045 Hotfix (971961, 975542)
if((hotfix_missing(name:"971961") == 0) || (hotfix_missing(name:"975542") == 0)){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Jscript.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.6.0.8837") ||
     version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.6002.22144")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

else if(hotfix_check_sp(xp:3) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.6002.22144") ||
       version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.22885")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"5.6.0.8837")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else
    security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # 5.8 < 5.8.6001.22886
    if(version_is_less(version:dllVer, test_version:"5.6.0.8837") ||
       version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.6002.22144") ||
       version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.22885")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else
    security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Jscript.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.0.18265") ||
       version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.18794")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.6002.18044") ||
         version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.18794")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.0.18265") ||
       version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.18794")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_in_range(version:dllVer, test_version:"5.7", test_version2:"5.7.6002.18044") ||
         version_in_range(version:dllVer, test_version:"5.8", test_version2:"5.8.6001.18794")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

