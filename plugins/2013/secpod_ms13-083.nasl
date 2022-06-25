###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Comctl32 Integer Overflow Vulnerability (2864058)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.903225");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-3195");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-10-09 08:59:40 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Comctl32 Integer Overflow Vulnerability (2864058)");

  script_tag(name:"summary", value:"This host is missing an critical security update according to Microsoft
  Bulletin MS13-083.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"A flaw exist in Comctl32.dll file which is caused by an integer overflow in
  the common control library.");

  script_tag(name:"affected", value:"Microsoft Windows 8

  Microsoft Windows Server 2012

  Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2003 x32/x64 Service Pack 2 and prior

  Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 for x64 Service Pack 1 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on the
  system with elevated privileges.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55106");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87402");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-083");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;2864058");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xpx64:3, win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Comctl32.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.82.3790.5190")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.82.6002.18879") ||
     version_in_range(version:sysVer, test_version:"5.82.6002.23000", test_version2:"5.82.6002.23150")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.82.7601.18201") ||
     version_in_range(version:sysVer, test_version:"5.82.7601.22000", test_version2:"5.82.7601.22375")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.82.9200.16657") ||
     version_in_range(version:sysVer, test_version:"5.82.9200.20000", test_version2:"5.82.9200.20764")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
