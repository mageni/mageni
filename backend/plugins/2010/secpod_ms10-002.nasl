###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (978207)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-22
#  - To detect file version 'mshtml.dll' on vista, win 2008 and win 7
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
  script_oid("1.3.6.1.4.1.25623.1.0.901097");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-22 16:43:14 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0244", "CVE-2010-0245",
                "CVE-2010-0246", "CVE-2010-0247", "CVE-2010-0248", "CVE-2010-0249");
  script_bugtraq_id(37883, 37135, 37884, 37891, 37895, 37892, 37893, 37894, 37815);
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (978207)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes via
  specially crafted HTML page in the context of the affected system and cause
  memory corruption.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 5.x/6.x/7.x/8.x");
  script_tag(name:"insight", value:"The Multiple flaws are due to:

  - Use-after-free error in the 'mshtml.dll' library

  - Input validation error when processing URLs, which could allow a
    malicious web site to execute a binary from the local client system

  - Memory corruption error when the browser accesses certain objects,
    which could be exploited by remote attackers to execute arbitrary code

  - Browser disabling an HTML attribute in appropriately filtered response
    data, which could be exploited to execute script in the context of the
    logged-on user in a different Internet domain.

  - Error when the browser attempts to access incorrectly initialized
    memory which could be exploited by remote attackers to execute arbitrary
    code.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-002.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0187");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-002");
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

# MS10-002 Hotfix (978207)
if(hotfix_missing(name:"978207") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:dllVer, test_version:"5.0", test_version2:"5.0.3884.1599") ||
         version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.2800.1643"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version: dllVer, test_version:"6.0", test_version2:"6.0.2900.3659")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16980")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21182")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18875")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22966")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
    	}
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        if(version_in_range(version: dllVer, test_version:"6.0", test_version2:"6.0.2900.5920")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16980")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21182")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18875")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22966")){
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
        # 8.0 <  8.0.6001.18876
        if(version_in_range(version: dllVer, test_version:"6.0", test_version2:"6.0.3790.4638") ||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16980")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21182")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18875")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22966")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}


sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16981")||
     version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21183")||
     version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18881")||
     version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22972"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }


  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
     SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18384")||
       version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22584")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18881")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22972")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version: dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18166")||
       version_in_range(version: dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22289")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18881")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22972")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_in_range(version: dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16489")||
     version_in_range(version: dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.20599")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
