###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer HTML Rendering Remote Memory Corruption Vulnerability (944533)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801702");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-13 17:08:42 +0100 (Thu, 13 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0076");
  script_bugtraq_id(27668);
  script_name("Microsoft Internet Explorer HTML Rendering Remote Memory Corruption Vulnerability (944533)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28903");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Feb/1019379.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-010.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code with
  the privileges of the application. Failed attacks may cause denial-of-service
  conditions.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 5.x/6.x/7.x");
  script_tag(name:"insight", value:"The flaw is due to,

  - Error in the way 'HTML' with certain layout combinations is interpreted
    which can be exploited to corrupt memory via a specially crafted web page.

  - Error in the way 'by' property of an 'animateMotion' SVG element is
    handled.

  - Error in the argument validation when processing images.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-010.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS08-010 Hotfix (944533)
if(hotfix_missing(name:"944533") == 0){
   exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3860.0999") ||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1606"))
      {
         security_message( port: 0, data: "The target host was found to be vulnerable" );
         exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3267") ||
           version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16607")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }

   else if(hotfix_check_sp(win2003:3) > 0)
   {
     SP = get_kb_item("SMB/Win2003/ServicePack");
     if("Service Pack 1" >< SP)
     {
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.3063")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
       }
       exit(0);
     }

     else if("Service Pack 2" >< SP)
     {
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4209") ||
          version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16607")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
       }
       exit(0);
     }
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\mshtml.dll");
if(dllVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6000.16608")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
