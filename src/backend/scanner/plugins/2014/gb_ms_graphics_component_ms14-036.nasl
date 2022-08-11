###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Graphics Component Multiple Vulnerabilities (2967487)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804596");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_bugtraq_id(67897, 67904);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-06-11 10:52:36 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Windows Graphics Component Multiple Vulnerabilities (2967487)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-036.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error within Unicode Scripts Processor.

  - An error within GDI+ when validating images.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 8.1 x32/x64

  Microsoft Windows Server 2012

  Microsoft Windows Server 2012 R2

  Microsoft Windows 2003 x32 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58583");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2957503");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2957509");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2) > 0)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Usp10.dll");
  if(!dllVer){
    exit(0);
  }

  if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"1.422.3790.5340")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"1.626.6002.18000", test_version2:"1.626.6002.19095")||
       version_in_range(version:dllVer, test_version:"1.626.6002.23000", test_version2:"1.626.6002.23385")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"1.626.7601.18000", test_version2:"1.626.7601.18453")||
       version_in_range(version:dllVer, test_version:"1.626.7601.22000", test_version2:"1.626.7601.22665")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Gdi32.dll");

  if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    if(version_in_range(version:dllVer2, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16908")||
       version_in_range(version:dllVer2, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21031")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  ## Currently we are not supporting Windows Server 2012 R2
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"system32\Dwrite.dll");

    if(version_is_less(version:dllVer2, test_version:"6.3.9600.17111") ||
       version_is_less(version:dllVer3, test_version:"6.3.9600.17111")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
