###############################################################################
# OpenVAS Vulnerability Test
#
# Windows Media Format Runtime Remote Code Execution Vulnerability (2847883)
#
# Authors:
# Arun kallavi <karun@secpod.com>
#
# Thanga Prakash S <tprakash@secpod.com> on 2013-08-30
# Updated According to revised Bulletin V3.0 (August 27, 2013)
#
# Copyright (c) 2013 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903223");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-3127");
  script_bugtraq_id(60980);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-07-10 12:37:46 +0530 (Wed, 10 Jul 2013)");
  script_name("Windows Media Format Runtime Remote Code Execution Vulnerability (2847883)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS13-057.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Flaw due to an unspecified error when handling WMV files.");

  script_tag(name:"affected", value:"Microsoft Windows 8

  Microsoft Windows Server 2003

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 7 x32 Service Pack 1 and prior

  Microsoft Windows Vista x32 Service Pack 2 and prior

  Microsoft Windows Server 2008 x32 Service Pack 2 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54062");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2847883");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-057");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3, win8:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Wmvdmod.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"\system32\Wmv9vcm.dll");
dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"\system32\Wmvdecod.dll");
if(!dllVer && !dllVer2 && !dllVer3){
  exit(0);
}

if(hotfix_check_sp(xp:4, win2003:3) > 0)
{
  ## updated on Aug-30-2013 for Wmvdmod.dll (9.0.0.4512) (10.0.0.4010) according to V3.0
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"9.0",test_version2:"9.0.0.4511") ||
       version_in_range(version:dllVer, test_version:"10.0.0.4300",test_version2:"10.0.0.4374") ||
       version_in_range(version:dllVer, test_version:"10.0.0.3700",test_version2:"10.0.0.3705") ||
       version_in_range(version:dllVer, test_version:"10.0.0.4080", test_version2:"10.0.0.4081") ||
       version_in_range(version:dllVer, test_version:"10.0.0.4000", test_version2:"10.0.0.4009")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    if((dllVer3 && version_in_range(version:dllVer3, test_version:"11.0", test_version2:"11.0.5721.5286")) ||
       (dllVer2 && version_in_range(version:dllVer2, test_version:"9.0.1", test_version2:"9.0.1.3072"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}
## Installing the 2803821 update on Windows Vista Service Pack 2
## or Windows Server 2008 Service Pack 2 downgrades the version of
## wmvdecod.dll from 11.0.6001.xxxx to 6.0.6002.yyyy.
## So this version check may not work later
## Might need to revisit later and verify.
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer3)
  {
    ## updated on Aug-30-2013 for Wmvdecod.dll (6.0.6002.18909) (6.0.6002.23182) according to V3.0
    if(dllVer3 != "6.0.6002.18909" && dllVer3 != "6.0.6002.23182")
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if(dllVer2)
  {
    if(dllVer2 != "0" && version_is_less(version:dllVer2, test_version:"9.0.1.3073"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(dllVer3 && dllVer3 != "0")
  {
    if(version_is_less(version:dllVer3, test_version:"6.1.7601.18220") ||
       version_in_range(version:dllVer3, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22401")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

## Win 8
else if(hotfix_check_sp(win8:1) > 0)
{
  if(dllVer3 && dllVer3 != "0")
  {
    if(version_is_less(version:dllVer3, test_version:"6.2.9200.16604") ||
       version_in_range(version:dllVer3, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20707")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
