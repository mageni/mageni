###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerability in Windows Shell Graphics Processing Could Allow Remote Code Execution (2483185)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902334");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2010-3970", "CVE-2011-0347");
  script_bugtraq_id(45662);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in Windows Shell Graphics Processing Could Allow Remote Code Execution (2483185)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42779");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024932");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0018");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code by
  tricking a user into opening or previewing a malformed Office file or browsing
  to a network share, UNC, or WebDAV location containing a specially crafted
  thumbnail image.");
  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to a signedness error in the 'CreateSizedDIBSECTION()'
  function within the Windows Shell graphics processor when parsing thumbnail bitmaps.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-006.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-006.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

## MS11-006 Hotfix
if((hotfix_missing(name:"2483185") == 0)){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Shell32.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
    	if(version_is_less(version:dllVer, test_version:"6.0.2900.6072")){
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
        if(version_is_less(version:dllVer, test_version:"6.0.3790.4822")){
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
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Shell32.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:3, win2008:3) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP) {
       SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18587")||
           version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22838")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"6.0.6002.18000" ,test_version2:"6.0.6002.18392")||
           version_in_range(version:dllVer, test_version:"6.0.6002.22000" ,test_version2:"6.0.6002.22573")){
             security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }
  }
}
