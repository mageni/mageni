###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft JScript and VBScript Scripting Engines Remote Code Execution Vulnerability (2514666)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902501");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0663");
  script_bugtraq_id(47249);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft JScript and VBScript Scripting Engines Remote Code Execution Vulnerability (2514666)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2510587");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2510581");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2510531");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0949");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-031.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page.");
  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2K3 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by an integer overflow error in the JScript and VBScript
  scripting engines when reallocating memory while decoding a script in order
  to run it, which could be exploited by remote attackers to execute arbitrary
  code via a malicious web page.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-031.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-031.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-031 Hotfix
if((hotfix_missing(name:"2510587") == 0) || (hotfix_missing(name:"2510581") == 0) ||
   (hotfix_missing(name:"2510531") == 0)) {
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Vbscript.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.6.0.8850") ||
       version_in_range(version:sysVer, test_version:"5.7", test_version2:"5.7.6002.22588")||
       version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.23140")){
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
    if(version_is_less(version:sysVer, test_version:"5.6.0.8850") ||
       version_in_range(version:sysVer, test_version:"5.7", test_version2:"5.7.6002.22588")||
       version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.23140")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.7.0.18599") ||
       version_in_range(version:sysVer, test_version:"5.7.0.22000", test_version2:"5.7.0.22853")||
       version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.19045")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.7.6002.18405") ||
       version_in_range(version:sysVer, test_version:"5.7.6002.22000", test_version2:"5.7.6002.22588")||
       version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.23140")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.8.7600.16762")||
     version_in_range(version:sysVer, test_version:"5.8.7600.20000", test_version2:"5.8.7600.20903")||
     version_in_range(version:sysVer, test_version:"5.8.7601.17000", test_version2:"5.8.7601.17561")||
     version_in_range(version:sysVer, test_version:"5.8.7601.21000", test_version2:"5.8.7601.21662")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
