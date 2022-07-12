###############################################################################
# OpenVAS Vulnerability Test
#
# Description: MS Internet Explorer 'Style' Object Remote Code Execution Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By
# Antu Sanadi <santu@secpod.com> on  2009-12-09
# Included the  Microsoft Bulletin MS09-072 #6097
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-23
#      - To detect file version 'mshtml.dll' on vista, win 2008 and win 7
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800727");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2493", "CVE-2009-3671", "CVE-2009-3672",
                "CVE-2009-3673", "CVE-2009-3674");
  script_bugtraq_id(37085);
  script_name("MS Internet Explorer 'Style' Object Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3437");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS09-072.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code via
  specially crafted HTML page in the context of the affected system and cause
  memory corruption thus causing remote machine compromise.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 5.x/6.x/7.x/8.x");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The 'tdc.ocx' ActiveX control being built with vulnerable Active Template
    Library (ATL) headers, which could allow the instantiation of arbitrary objects
    that can bypass certain security related policies.

  - Memory corruption error occurs when the browser attempts to access an object
    that has not been initialized or has been deleted, which could be exploited
    to execute arbitrary code via a specially crafted web page.

  - Memory corruption occurs when processing 'CSS' objects.

  - Race condition occurs while repetitively clicking between two elements at
    a fast rate, which could be exploited to execute arbitrary code via a
    specially crafted web page.

  - A dangling pointer during deallocation of a circular dereference for a
    CAttrArray object, which could be exploited to execute arbitrary code via
    a specially crafted web page.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-072.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(hotfix_missing(name:"976325") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(!vers){
    exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3882.2699") ||
     version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1641")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:vers, test_version:"6.0.2900.0000", test_version2:"6.0.2900.3639")||
       version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.21128")||
       version_in_range(version:vers, test_version:"8.0", test_version2:"8.0.6001.18853")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
   if( version_in_range(version:vers, test_version:"6.0.2900.0000", test_version2:"6.0.2900.5896")||
       version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16944") ||
       version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21147") ||
       version_in_range(version:vers, test_version:"8.0", test_version2:"8.0.6001.18853")||
       version_in_range(version:vers, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22944")){
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
    if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4610") ||
       version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16944") ||
       version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.00.6000.21147")||
       version_in_range(version:vers, test_version:"8.0.6001.00000", test_version2:"8.0.6001.18853")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}
dllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18348") ||
       version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.6001.18864")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6002.18129")){
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
    if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18348") ||
       version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.6001.18864")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6002.18129")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.7600.16465")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

