###############################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Security Update for Internet Explorer (961260)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-03
#        - To detect file version 'mshtml.dll' on vista and win 2008
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
  script_oid("1.3.6.1.4.1.25623.1.0.900078");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0075", "CVE-2009-0076");
  script_bugtraq_id(33627, 33628);
  script_name("Cumulative Security Update for Internet Explorer (961260)");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation results in memory corruption by executing
  arbitrary code when user visits a specially crafted web page.");
  script_tag(name:"affected", value:"Internet Explorer 7/8 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows vista SP1 and prior
  Internet Explorer 7 on MS Windows 2008 server SP1 and prior");
  script_tag(name:"insight", value:"- An error occurs when IE browser tries to use a previously deleted object
    related to CFunctionPointer.

  - An error exists when XHTML strict mode is used in the zoom style directive
    in conjunction with other directives within the Cascading Style Sheets (CSS)
    stylesheet in a crafted HTML document.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-002.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS09-002 Hotfix (961260)
if(hotfix_missing(name:"961260") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(xp:4, win2003:3) > 0)
    {
      if(version_in_range(version: vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16808")||
         version_in_range(version: vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20996")||
         version_in_range(version: vers, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18258")||
         version_in_range(version: vers, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22351"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:2, win2008:2) > 0)
    {
      if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16808")||
         version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20995")||
         version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18258")||
         version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22351"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP){
        SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18202")||
           version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22354"))
        {
           security_message( port: 0, data: "The target host was found to be vulnerable" );
           exit(0);
        }
      }
    }
  }
}

