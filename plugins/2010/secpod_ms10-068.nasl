###############################################################################
# OpenVAS Vulnerability Test
#
# MS Local Security Authority Subsystem Service Privilege Elevation Vulnerability (983539)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902244");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0820");
  script_name("MS Local Security Authority Subsystem Service Privilege Elevation Vulnerability (983539)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/981550");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/982000");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2389");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attacker who has previously
  authenticated with the LSASS server to execute arbitrary code with SYSTEM
  privileges.");
  script_tag(name:"affected", value:"Microsoft Windows 7
  Microsoft Windows Vista Service Pack 2
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows Server 2003 Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by a heap overflow error in the Local Security Authority
  Subsystem Service (LSASS) when handling Lightweight Directory Access Protocol
  (LDAP) messages in certain implementations of Active Directory, Active
  Directory Application Mode (ADAM), and Active Directory Lightweight Directory
  Service (AD LDS).");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-068.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-068.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

# Active Directory
if((hotfix_missing(name:"981550") == 1) &&
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
      if(hotfix_check_sp(win2003:3) > 0)
      {
        SP = get_kb_item("SMB/Win2003/ServicePack");
        if("Service Pack 2" >< SP)
        {
          if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.4754")){
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
if((hotfix_missing(name:"982000)") == 1) &&
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
          if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4722")){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}

if((hotfix_missing(name:"981550") == 0)){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        item:"PathName");
if(!sysPath){
 exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                   string:sysPath + "\system32\Ntdsai.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18461")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18244")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

 else if(hotfix_check_sp(win2008:2) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"1.626.6001.18461")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18244")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16612")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
