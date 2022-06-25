###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-041.nasl 2014-07-09 08:00:36Z july$
#
# Microsoft DirectShow Elevation of Privileges Vulnerability (2975681)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804670");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-2780");
  script_bugtraq_id(68392);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-07-09 08:09:40 +0530 (Wed, 09 Jul 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft DirectShow Elevation of Privileges Vulnerability (2975681)");


  script_tag(name:"summary", value:"This host is missing a important security update according to Microsoft
Bulletin MS14-041.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an error in the way DirectShow handles objects in the memory.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain elevated privileges,
execute code within the context of the logged on user and take complete
control of an affected system.");
  script_tag(name:"affected", value:"Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior
Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2972280");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2973932");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-041");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3,
                   win2008x64:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win8_1:1, win8_1x64:1, win2012R2:1) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\qedit.dll");
if(!sysVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.6.6002.19118") ||
     version_in_range(version:sysVer, test_version:"6.6.6002.23000", test_version2:"6.6.6002.23417")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.6.7601.18501") ||
     version_in_range(version:sysVer, test_version:"6.6.7601.22000", test_version2:"6.6.7601.22715")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.6.9200.17023") ||
     version_in_range(version:sysVer, test_version:"6.6.9200.20000", test_version2:"6.6.9200.21139")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.6.9600.16672")||
     version_in_range(version:sysVer, test_version:"6.6.9600.17000", test_version2:"6.6.9600.17199")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
