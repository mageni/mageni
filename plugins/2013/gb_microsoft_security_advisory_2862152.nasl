###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft DirectAccess Security Advisory (2862152)
#
# Authors:
# Shakeel <bhatshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804143");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2013-3876");
  script_bugtraq_id(63666);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-11-14 14:28:18 +0530 (Thu, 14 Nov 2013)");
  script_name("Microsoft DirectAccess Security Advisory (2862152)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
  advisory (2862152).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"The flaw is due to improper verification of DirectAccess server connections
  to DirectAccess clients by DirectAccess.");

  script_tag(name:"affected", value:"Microsoft Windows XP x32 Edition Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows 8

  Microsoft Windows Server 2012

  Microsoft Windows 8.1 x32/x64");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to intercept the target user's
  network traffic and potentially determine their encrypted domain credentials.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63666");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2014/2862152");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
  win7x64:2, win2008:3, win2008x64:3, win2008r2:2, win8:1, win2012:1,
  win8_1:1, win8_1x64:1)<= 0){
    exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

oakleyVer = fetch_file_version(sysPath:sysPath, file_name:"system32\oakley.dll");
fwpuVer = fetch_file_version(sysPath:sysPath, file_name:"system32\fwpuclnt.dll");

if(oakleyVer  || fwpuVer )
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:oakleyVer, test_version:"5.1.2600.6462")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if(hotfix_check_sp(xpx64:3,win2003x64:3,win2003:3) > 0)
  {
    if(version_is_less(version:oakleyVer, test_version:"5.2.3790.5238")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.0.6002.18960") ||
       version_in_range(version:fwpuVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23242")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.1.7601.18283") ||
       version_in_range(version:fwpuVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22478")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.2.9200.16634") ||
       version_in_range(version:fwpuVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20568")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  ## Win 8.1
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.3.9600.16384")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
