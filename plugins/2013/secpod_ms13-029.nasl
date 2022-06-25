###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft RDP ActiveX Control Remote Code Execution Vulnerability (2828223)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901217");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-1296");
  script_bugtraq_id(58874);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-04-10 12:20:24 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft RDP ActiveX Control Remote Code Execution Vulnerability (2828223)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52911");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2813347");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2813345");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-029");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the current user.");
  script_tag(name:"insight", value:"Flaw is in Remote Desktop ActiveX control and can be exploited to access
  an object in memory that has been freed.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-029.");
  script_tag(name:"affected", value:"Remote Desktop Connection 6.1 Client

  - Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior

  Remote Desktop Connection 7.0 Client

  - Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
   win7x64:2, win2008:3, win2008r2:2 ) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Tsgqec.dll");
if(!exeVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_in_range(version:exeVer, test_version:"6.1.7600.17000", test_version2:"6.1.7600.17232") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.21000", test_version2:"6.1.7600.21447") ||
     version_in_range(version:exeVer, test_version:"6.0.6001.23000", test_version2:"6.0.6001.23190")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  if(version_in_range(version:exeVer, test_version:"6.0.6001.17000", test_version2:"6.0.6001.17999") ||
     version_in_range(version:exeVer, test_version:"6.0.6001.23000", test_version2:"6.0.6001.23190")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_in_range(version:exeVer, test_version:"6.1.7600.17000", test_version2:"6.1.7600.17232") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.21000", test_version2:"6.1.7600.21447") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18004") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23074")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  if(version_in_range(version:exeVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18004") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23074")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:exeVer, test_version:"6.1.7600.17000", test_version2:"6.1.7600.17232") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.21448", test_version2:"6.1.7600.21447") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.18079", test_version2:"6.1.7601.18078") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22251")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
