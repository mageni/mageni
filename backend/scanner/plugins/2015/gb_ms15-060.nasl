###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Common Controls Remote Code Execution Vulnerability (3059317)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805399");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-1756");
  script_bugtraq_id(75017);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-06-10 10:08:31 +0530 (Wed, 10 Jun 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Common Controls Remote Code Execution Vulnerability (3059317)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-060.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Microsoft Common Controls,
  when it accesses an object in memory that has not been correctly initialized or
  has been deleted");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code within the context of the application
  that uses the ActiveX control.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3059317");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-060");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
              win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\comctl32.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.82.6002.19373")||
     version_in_range(version:dllVer, test_version:"5.82.6002.23000", test_version2:"5.82.6002.23680")||
     version_in_range(version:dllVer, test_version:"6.10.6002.19000", test_version2:"6.10.6002.19372")||
     version_in_range(version:dllVer, test_version:"6.10.6002.23000", test_version2:"6.10.6002.23680")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.82.7601.18837")||
     version_in_range(version:dllVer, test_version:"5.82.7601.23000", test_version2:"5.82.7601.23038")||
     version_in_range(version:dllVer, test_version:"6.10.7601.18000", test_version2:"6.10.7601.18836")||
     version_in_range(version:dllVer, test_version:"6.10.7601.23000", test_version2:"6.10.7601.23038")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.82.9200.17359")||
     version_in_range(version:dllVer, test_version:"5.82.9200.21000", test_version2:"5.82.9200.21471")||
     version_in_range(version:dllVer, test_version:"6.10.9200.17000", test_version2:"6.10.9200.17358")||
     version_in_range(version:dllVer, test_version:"6.10.9200.21000", test_version2:"6.10.9200.21471")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.82.9600.17810")||
    version_in_range(version:dllVer, test_version:"6.10.9600.17000", test_version2:"6.10.9600.17809")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
