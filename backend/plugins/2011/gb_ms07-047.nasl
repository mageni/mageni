###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in Windows Media Player Could Allow Remote Code Execution (936782)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801714");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-3037", "CVE-2007-3035");
  script_bugtraq_id(25307, 25305);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Vulnerabilities in Windows Media Player Could Allow Remote Code Execution (936782)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/26433");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/35895");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms07-047.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application.");
  script_tag(name:"affected", value:"Microsoft Windows Media Player 7.1
  Microsoft Windows Media Player 9
  Microsoft Windows Media Player 10");
  script_tag(name:"insight", value:"The flaws are due to an errors in the parsing of header information
  in skin files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-047.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3) <= 0){
  exit(0);
}

## MS07-047 Hotfix
if(hotfix_missing(name:"936782") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Wmp.dll");
  dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"Wmpui.dll");
  if(dllVer || dllVer2)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.0.3353") ||
         version_in_range(version:dllVer2, test_version:"7.0", test_version2:"7.10.0.3079")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }

    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.0.3353")||
           version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.4057")||
           version_in_range(version:dllVer, test_version:"11", test_version2:"11.0.5721.5229")){
              security_message( port: 0, data: "The target host was found to be vulnerable" );
         }
      }

      if("Service Pack 3" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.4057")||
           version_in_range(version:dllVer, test_version:"11", test_version2:"11.0.5721.5229")){
              security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.3708")){
              security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.3997")){
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

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\wmp.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"11", test_version2:"11.0.6000.6335")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
