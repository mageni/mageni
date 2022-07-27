###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IIS Authentication Remote Code Execution Vulnerability (982666)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-15
#       - To detect required file version on vista, win 2008 and win 7
#
# Updated by : Sooraj KS <kssooraj@secpod.com> on 2012-05-15
#       - Added IIS installation confirmation.
#       - Added extended protection confirmation for IIS 6.0
#       - Updated to support GDR and LDR versions.
#       - Removed get_file_version function.
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901120");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_bugtraq_id(40573);
  script_cve_id("CVE-2010-1256");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Microsoft IIS Authentication Remote Code Execution Vulnerability (982666)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40079/");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-040.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_iis_detect_win.nasl");
  script_mandatory_keys("MS/IIS/Ver", "SMB/registry_enumerated");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with the privileges of the server.");
  script_tag(name:"affected", value:"Internet Information Services 6.0 on,

  - Microsoft Windows 2003 Service Pack 2 and prior.
  Internet Information Services 7.0 on,

  - Microsoft Windows Vista SP1/SP2 and prior.
  Internet Information Services 7.5 on,

  - Microsoft Windows 7");
  script_tag(name:"insight", value:"The flaw is due to an error in Internet Information Services (IIS)
  when parsing authentication information when it is configured for
  'Extended Protection for Authentication', which could allow remote
  code execution while processing a specially crafted HTTP request.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS10-040.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-040.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

iisVer = get_kb_item("MS/IIS/Ver");
if(!iisVer){
  exit(0);
}

if(hotfix_missing(name:"982666") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\Http.sys");
  if(!sysVer){
    exit(0);
  }
}

if(hotfix_check_sp(win2003:3) > 0)
{
  key = "SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\extendedProtection";
  if(registry_key_exists(key:key))
  {
    ext_prt = registry_get_dword(key:key, item:"tokenChecking");
    if(!ext_prt || ext_prt != 1) {
      exit(0);
    }
  }

  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4693")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"System32\drivers\Http.sys");
  if(!sysVer){
   exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18428") ||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22674")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18210") ||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22387")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\inetsrv\authsspi.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"7.5.7600.16576") ||
     version_in_range(version:dllVer, test_version:"7.5.7600.20000", test_version2:"7.5.7600.20693")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
