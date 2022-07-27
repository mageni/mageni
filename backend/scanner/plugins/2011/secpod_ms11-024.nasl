###############################################################################
# OpenVAS Vulnerability Test
#
# Windows Fax Cover Page Editor Remote Code Execution Vulnerability (2527308)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu sanadi <santu@secpod.com> on 2011-05-18
#  - Updated null check for versions
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
  script_oid("1.3.6.1.4.1.25623.1.0.902408");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2010-3974");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Windows Fax Cover Page Editor Remote Code Execution Vulnerability (2527308)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2491683");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2506212");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-024.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain the same user rights as
  the logged-on user. Users whose accounts are configured to have fewer user
  rights on the system could be less impacted than users who operate with
  administrative user rights.");
  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2K3 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to error in fax cover page editor, when user opened a
  specially crafted fax cover page file (.cov) using the windows fax cover page
  editor will trigger a memory corruption error in the Fax Cover Page Editor
  (fxscover.exe) and execute arbitrary code on the target system.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-024.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-024.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-024 Hotfix (2491683) and (2506212)
if((hotfix_missing(name:"2491683") == 0) && (hotfix_missing(name:"2506212") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\fxscover.exe");
sysVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Mfc42.dll");
if( ! sysVer1 && ! sysVer2 ) exit( 0 );

## Avoid passing FALSE values to the version_* functions later if fetch_file_version() returns FALSE
if( ! sysVer1 ) sysVer1 = "unknown";
if( ! sysVer2 ) sysVer2 = "unknown";

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer1, test_version:"5.2.2600.6078") ||
       version_is_less(version:sysVer2, test_version:"6.2.8081.0")){
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
    if(version_is_less(version:sysVer1, test_version:"5.2.3790.4829") ||
       version_is_less(version:sysVer2, test_version:"6.6.8064.0")){
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
    if(version_in_range(version:sysVer1, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18596")||
       version_in_range(version:sysVer1, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22851") ||
       version_is_less(version:sysVer2, test_version:"6.6.8064.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:sysVer1, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18402")||
       version_in_range(version:sysVer1, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22585") ||
       version_is_less(version:sysVer2, test_version:"6.6.8064.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:sysVer1, test_version:"6.1.7600.16759")||
     version_is_less(version:sysVer2, test_version:"6.6.8064.0") ||
     version_in_range(version:sysVer1, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20899")||
     version_in_range(version:sysVer1, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17558")||
     version_in_range(version:sysVer1, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21658")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
