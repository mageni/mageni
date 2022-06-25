###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2586448)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901208");
  script_version("2019-05-20T11:12:48+0000");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_cve_id("CVE-2011-1993", "CVE-2011-1995", "CVE-2011-1996", "CVE-2011-1997",
                "CVE-2011-1998", "CVE-2011-1999", "CVE-2011-2000", "CVE-2011-2001");
  script_bugtraq_id(49947, 49960, 49961, 49962, 49963, 49964, 49965, 49966);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2586448)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46400");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2586448");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-081");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed exploit attempts will result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x");

  script_tag(name:"insight", value:"Multiple flaws are due to the way Internet Explorer handles,

  - dereferenced memory address aka 'Select Element'.

  - accessing an object that was not properly initialized aka 'Jscript9.dll',
  'OLEAuto32.dll'.

  - accessing a deleted object aka 'Body Element', 'OnLoad Event',
   'Option Element', 'Scroll Event'.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-081.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(ieVer !~ "^[6-9]\."){
  exit(0);
}

## MS11-081 Hotfix (2586448)
if(hotfix_missing(name:"2586448") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"6.0.2900.0000", test_version2:"6.0.2900.6147") ||
       version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17103")||
       version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21305")||
       version_in_range(version:dllVer, test_version:"8.0.6001.10000", test_version2:"8.0.6001.19153") ||
       version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23249")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"6.0.3790.0000", test_version2:"6.0.3790.4903") ||
       version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17103")||
       version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21305")||
       version_in_range(version:dllVer, test_version:"8.0.6001.10000", test_version2:"8.0.6001.19153") ||
       version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23249")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18509")||
       version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22697")||
       version_in_range(version:dllVer, test_version:"8.0.6001.10000", test_version2:"8.0.6001.19153")||
       version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23249")||
       version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16436")||
       version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20536")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16890")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.21061")||
     version_in_range(version:dllVer, test_version:"8.0.7601.10000", test_version2:"8.0.7601.17698")||
     version_in_range(version:dllVer, test_version:"8.0.7601.20000", test_version2:"8.0.7601.21829")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16436")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20536")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
