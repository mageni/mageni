###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft JScript and VBScript Engines Remote Code Execution Vulnerability (2706045)
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
  script_oid("1.3.6.1.4.1.25623.1.0.903037");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-2523");
  script_bugtraq_id(54945);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-08-15 11:13:45 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft JScript and VBScript Engines Remote Code Execution Vulnerability (2706045)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50243/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2706045");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-056");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Windows 7 x64 Edition Service Pack 1 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 2003 x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaw is caused by an integer overflow error in the JScript and VBScript
  scripting engines when calculating the size of an object in memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-056.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xpx64:3, win2003x64:3, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:dllPath, file_name:"System32\Vbscript.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xpx64:3, win2003x64:3) > 0){
  if(version_is_less(version:dllVer, test_version:"5.8.6001.23380")){
    report = report_fixed_ver(file_checked:dllPath + "System32\Vbscript.dll",
             file_version:dllVer, vulnerable_range:"< 5.8.6001.23380");
    security_message(port:0, data:report);
  }
  exit(0);
}

## Currently no support for Vista and Windows Server 2008 64 bit

else if(hotfix_check_sp(win7x64:2, win2008r2:2) > 0){
  if(version_is_less(version:dllVer, test_version:"5.8.7600.17045") ||
     version_in_range(version:dllVer, test_version:"5.8.7600.20000", test_version2:"5.8.7600.21237")||
     version_in_range(version:dllVer, test_version:"5.8.7601.17000", test_version2:"5.8.7601.17865")||
     version_in_range(version:dllVer, test_version:"5.8.7601.21000", test_version2:"5.8.7601.22023")){
    report = report_fixed_ver(file_checked:dllPath + "System32\Vbscript.dll",
             file_version:dllVer, vulnerable_range:"< 5.8.7600.17045, 5.8.7600.20000 - 5.8.7600.21237, 5.8.7601.17000 - 5.8.7601.17865, 5.8.7601.21000 - 5.8.7601.22023");
    security_message(port:0, data:report);
  }
}

exit(99);