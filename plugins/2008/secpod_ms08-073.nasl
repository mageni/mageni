###############################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Security Update for Internet Explorer (958215)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-06
# - To detect file version 'mshtml.dll' on vista and win 2008
#
# Copyright: SecPod
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
  script_oid("1.3.6.1.4.1.25623.1.0.900062");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260", "CVE-2008-4261");
  script_bugtraq_id(32586, 32593, 32595, 32596);
  script_name("Cumulative Security Update for Internet Explorer (958215)");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS08-073");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could result in stack based buffer overflow by
  sending overly long specially crafted file via web page to corrupt heap
  memory.");
  script_tag(name:"affected", value:"Internet Explorer 7 on MS Windows Vista
  Internet Explorer 6 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows 2008 Server
  Internet Explorer 5.01 and 6 on MS Windows 2000");
  script_tag(name:"insight", value:"The flaws are due to

  - error when handling parameters passed to unspecified navigation methods.

  - error when fetching a file with an overly long path from a WebDAV share.

  - unspecified use-after-free error.

  - a boundary error when processing an overly long filename extension
    specified inside an EMBED tag.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-073.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

ieVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer",
                        item:"Version");
if(!ieVer){
  ieVer = registry_get_sz(item:"IE",
          key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
}

if(!ieVer){
  exit(0);
}

# MS08-073 Hotfix (958215)
if(hotfix_missing(name:"958215") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3870.1499")||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1616")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }

    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:vers, test_version:"6.0.2900.0000", test_version2:"6.0.2900.3461")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16761")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20934")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 3" >< SP)
      {
        if(version_in_range(version:vers, test_version:"6.0.2900.0000", test_version2:"6.0.2900.5693")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16761")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20934")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      exit(0);
    }

    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:vers, test_version:"6.0.3790.0000", test_version2:"6.0.3790.3228")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16761")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20934")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:vers, test_version:"6.0.3790.0000", test_version2:"6.0.3790.4391")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16761")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20934")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      exit(0);
    }
  }
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:2, win2008:2) > 0)
    {
      if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16763")||
         version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20936"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP){
         SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18156")||
           version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22287"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
      exit(0);
    }
  }
}

