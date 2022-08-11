###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Active Directory Denial of Service Vulnerability (973309)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-01-10
#     - To get required file version on windows 2008 server
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901048");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-12 15:21:24 +0100 (Thu, 12 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1928");
  script_bugtraq_id(36918);
  script_name("Microsoft Windows Active Directory Denial of Service Vulnerability (973309)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/973037");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/973039");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3192");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-066.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the server which may result
  in Denial of Service.");
  script_tag(name:"affected", value:"Microsoft Windows 2K  Service Pack 4 and prior
  Microsoft Windows XP  Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows 2008 server Service Pack 2 and prior");
  script_tag(name:"insight", value:"This issue is caused by an error in implementations of Active Directory
  Application Mode (ADAM) and Active Directory Lightweight Directory Service
  (AD LDS) when processing malformed LDAP or LDAPS requests.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-066.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:3) <= 0){
  exit(0);
}

# Active Directory
if((hotfix_missing(name:"973037") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS\Performance"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(dllPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    ntdsaFile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                             string:dllPath + "\Ntdsa.dll");
    ntdsaVer = GetVer(file:ntdsaFile, share:share);
    if(ntdsaVer != NULL)
    {
      if(hotfix_check_sp(win2k:5) > 0)
      {
        if(version_is_less(version:ntdsaVer, test_version:"5.0.2195.7313"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
      else if(hotfix_check_sp(win2003:3) > 0)
      {
        SP = get_kb_item("SMB/Win2003/ServicePack");
        if("Service Pack 2" >< SP)
        {
          if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.4568")){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }

  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Ntdsai.dll");
    if(dllVer)
    {
      if(hotfix_check_sp(win2008:3) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");
        if("Service Pack 1" >< SP)
        {
          if(version_is_less(version:dllVer, test_version:"6.0.6001.18281")){
             security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }

        if("Service Pack 2" >< SP)
        {
          if(version_is_less(version:dllVer, test_version:"6.0.6002.18058")){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
           exit(0);
        }
         security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}

# Active Directory Application Mode
if((hotfix_missing(name:"973039") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\ADAM\Linkage"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(dllPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    adamdsaFile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                              string:dllPath - "system32" + "ADAM\Adamdsa.dll");
    adamdsaVer = GetVer(file:adamdsaFile, share:share);
    if(adamdsaVer != NULL)
    {
      if(hotfix_check_sp(xp:4, win2003:3) > 0)
      {
        XPSP = get_kb_item("SMB/WinXP/ServicePack");
        k3SP = get_kb_item("SMB/Win2003/ServicePack");
        if(XPSP =~ "Service Pack (2|3)" || ("Service Pack 2" >< k3SP))
        {
          if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4569")){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
