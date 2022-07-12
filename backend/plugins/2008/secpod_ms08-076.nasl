###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in Windows Media Components Could Allow Remote Code Execution (959807)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-07
#       - To detect required file version on vista and win 2008
#
# Copyright: SecPod
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
  script_oid("1.3.6.1.4.1.25623.1.0.900060");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-3009", "CVE-2008-3010");
  script_bugtraq_id(32653, 32654);
  script_name("Vulnerabilities in Windows Media Components Could Allow Remote Code Execution (959807)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-076.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to disclose NTLM credentials
  to gain access with the privileges of a target user via replay attacks.");
  script_tag(name:"affected", value:"Microsoft Windows 2K/XP/2003");
  script_tag(name:"insight", value:"The flaws are due to

  - an error within the Service Principal Name (SPN) implementation when
    handling NTLM credentials.

  - an error when handling ISATAP URLs.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-076.");
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

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

activeKey = "SOFTWARE\Microsoft\Active setup\Installed Components\";
playerVer = registry_get_sz(item:"Version",
            key:"SOFTWARE\Microsoft\Active setup\Installed Components" +
                "\{22d6f312-b0f6-11d0-94ab-0080c74c7e95}");
if(playerVer)
{
  if(hotfix_missing(name:"954600") == 1)
  {

    dllVer = fetch_file_version(sysPath:sysPath, file_name:"Strmdll.dll");
    if(dllVer != NULL)
    {
      if(version_is_less(version:dllVer, test_version:"4.1.0.3937"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Wmvcore.dll");
if(dllVer)
{
  if(hotfix_missing(name:"952069") == 1)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_is_less(version:dllVer, test_version:"9.0.0.3268")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"9.0",
                            test_version2:"9.0.0.3267")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        else if(version_in_range(version:dllVer, test_version:"10.0",
                                 test_version2:"10.0.0.3702")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        else if(version_in_range(version:dllVer, test_version:"11.0",
                                 test_version2:"11.0.5721.5250")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 3" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"9.0",
                            test_version2:"9.0.0.4503")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        else if(version_in_range(version:dllVer, test_version:"10.0",
                                 test_version2:"10.0.0.3702")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        else if(version_in_range(version:dllVer, test_version:"11.0",
                                 test_version2:"11.0.5721.5250")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10.0",
                            test_version2:"10.0.0.3710")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10.0",
                            test_version2:"10.0.0.4000")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

dllPath = smb_get_system32root();
if(!dllPath){
   exit(0);
}

dllVer = fetch_file_version(sysPath:dllPath, file_name:"Wmvcore.dll");
if(dllVer)
{
  if(hotfix_missing(name:"952069") == 1)
  {
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6001.7000")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }
    }

    else if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6001.7000")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }
  }
}

if(hotfix_missing(name:"952068") == 1)
{
  if(hotfix_check_sp(win2k:5) > 0)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"\windows media\server\Nsum.exe");
    if(dllVer != NULL)
    {
      if(version_is_less(version:dllVer, test_version:"4.1.0.3936")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
  else if(hotfix_check_sp(win2003:3) > 0)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"\windows media\server\Wmsserver.dll");
    if(dllVer != NULL)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.1.1.3845")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.1.1.5000")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  dllPath = smb_get_system32root();
  if(!dllPath){
    exit(0);
  }

 dllVer = fetch_file_version(sysPath:dllPath, file_name:"\windows media\server\Wmsserver.dll");
 if(dllVer)
  {
    if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.5.6001.18161")){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
           exit(0);
      }
    }
  }
}
