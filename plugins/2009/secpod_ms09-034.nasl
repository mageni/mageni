###############################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Security Update for Internet Explorer (972260)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-30
#  - To detect file version 'mshtml.dll' on vista and win 2008
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-05-18
#  - Added exit() to avoid FP check for windows XP SP3
#
# Copyright:
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
  script_oid("1.3.6.1.4.1.25623.1.0.900906");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-29 15:02:57 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1917", "CVE-2009-1918", "CVE-2009-1919");
  script_bugtraq_id(35831, 35827);
  script_name("Cumulative Security Update for Internet Explorer (972260)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/972260");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-034");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Specially crafted HTML page will let the attacker execute arbitrary
  codes in the context of the affected system and cause memory corruption.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 5.x/6.x/7.x/8.x");
  script_tag(name:"insight", value:"Multiple errors occur due to the way IE

  - handles memory objects,

  - handles table operations,

  - access a previously deleted object.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-034.");
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

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS09-034 Hotfix (972260)
if(hotfix_missing(name:"972260") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3879.2199")||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1633"))
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
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3602")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16889")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
           version_in_range(version:vers, test_version:"8.0.6001.16000", test_version2:"8.0.6001.18811")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22901")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # or 8.0 < 8.0.6001.18806
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.5847")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16889")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
           version_in_range(version:vers, test_version:"8.0.6001.16000", test_version2:"8.0.6001.18811")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22901")){
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
        # or 8.0 < 8.0.6001.18812
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4554")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16889")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
           version_in_range(version:vers, test_version:"8.0.6001.16000", test_version2:"8.0.6001.18811")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22901")){
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
  if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16889")||
     version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
     version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18812")||
     version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22902"))
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
    if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18293")||
       version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22474")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18812")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22902")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version: dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18070")||
       version_in_range(version: dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22179")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18812")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22902")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
