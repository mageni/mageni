###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Networking Components Remote Code Execution Vulnerabilities (2733594)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903036");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-1850", "CVE-2012-1851", "CVE-2012-1852", "CVE-2012-1853");
  script_bugtraq_id(54921, 54928, 54931, 54940);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-08-15 09:04:09 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft Windows Networking Components Remote Code Execution Vulnerabilities (2733594)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50245/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2705219");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2712808");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-054");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on an affected system or cause denial of service condition.");
  script_tag(name:"affected", value:"Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaws are due to

  - The way windows networking components handle a specially crafted RAP
    response.

  - A format string error within the print spooler service can be exploited
    via a specially crafted response.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-054.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:dllPath, file_name:"system32\Netapi32.dll");

if(dllVer)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"5.1.2600.6260")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"5.2.3790.5030")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18659") ||
       version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22886")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"6.1.7600.17056") ||
       version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21255")||
       version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17886")||
       version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22043"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
  }
}

dllVer1 = fetch_file_version(sysPath:dllPath, file_name:"system32\Localspl.dll");

if(dllVer1)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:dllVer1, test_version:"5.1.2600.6226")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer1, test_version:"5.2.3790.5002")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer1, test_version:"6.0.6002.18631") ||
       version_in_range(version:dllVer1, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22856")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer1, test_version:"6.1.7600.17023") ||
       version_in_range(version:dllVer1, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21213")||
       version_in_range(version:dllVer1, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17840")||
       version_in_range(version:dllVer1, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21993")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
