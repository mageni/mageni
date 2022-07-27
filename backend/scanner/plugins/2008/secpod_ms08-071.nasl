###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in GDI Could Allow Remote Code Execution (956802)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-07
#        - To detect file version 'gdi32.dll' on vista and win 2008
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
  script_oid("1.3.6.1.4.1.25623.1.0.900059");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2249", "CVE-2008-3465");
  script_bugtraq_id(32634, 32637);
  script_name("Vulnerabilities in GDI Could Allow Remote Code Execution (956802)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-071.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code on the remote
  system and cause heap based buffer overflow via a specially crafted WMF file.");

  script_tag(name:"affected", value:"Microsoft Windows 2K/XP/2003/Vista/2008 Server");

  script_tag(name:"insight", value:"The flaw is due to,

  - an overflow error in GDI when processing headers in Windows Metafile (WMF)
    files.

  - an error in the the way the GDI handles file size parameters in WMF files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-071.");

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

if(hotfix_missing(name:"956802") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"gdi32.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_is_less(version:dllVer, test_version:"5.0.2195.7205")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"5.1.2600.3466")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 3" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"5.1.2600.5698")){
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
        if(version_is_less(version:dllVer, test_version:"5.2.3790.3233")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"5.2.3790.4396")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
      else security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"gdi32.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18159")){
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
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18159")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }
    }
  }
}

