###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-040.nasl 2014-07-09 09:10:36Z july$
#
# MS Windows Ancillary Function Driver Elevation of Privilege Vulnerability (2975684)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804671");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-1767");
  script_bugtraq_id(68394);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-07-09 09:19:40 +0530 (Wed, 09 Jul 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("MS Windows Ancillary Function Driver Elevation of Privilege Vulnerability (2975684)");


  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
Bulletin MS14-040.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to a double-free error in the Ancillary Function Driver within
'afd.sys'.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain elevated privileges and
execute arbitrary code and take complete control of an affected system.");
  script_tag(name:"affected", value:"Microsoft Windows 2003 x32 Service Pack 3 and prior
Microsoft Windows 2003 x64 Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior
Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59778");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2961072");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2973408");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-040");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1, win2012R2:1) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

afdSysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Drivers\afd.sys");
if(!afdSysVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"5.2.3790.5358")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"6.0.6002.19115") ||
     version_in_range(version:afdSysVer, test_version:"6.6.6002.23000", test_version2:"6.0.6002.23413")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"6.1.7601.18489") ||
     version_in_range(version:afdSysVer, test_version:"6.6.7601.22000", test_version2:"6.1.7601.22704")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"6.2.9200.17014") ||
     version_in_range(version:afdSysVer, test_version:"6.6.9200.20000", test_version2:"6.2.9200.21132")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:afdSysVer, test_version:"6.3.9600.16668")||
     version_in_range(version:afdSysVer, test_version:"6.6.9600.17000", test_version2:"6.3.9600.17193")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
