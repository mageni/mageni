###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Active Directory LDAPS Authentication Bypass Vulnerability (2630837)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902487");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2011-2014");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-11-09 12:52:09 +0530 (Wed, 09 Nov 2011)");
  script_name("Microsoft Windows Active Directory LDAPS Authentication Bypass Vulnerability (2630837)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46755/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2601626");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2616310");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-086");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to use revoked
  certificate to authenticate to the Active Directory domain and gain
  access to network resources or run code under the privileges of a
  specific authorized user with which the certificate is associated.");
  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2003 Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to an error in Active Directory when configured to
  use LDAP over SSL. It fails to validate the revocation status of an SSL
  certificate against the CRL (Certificate Revocation List) associated with
  the domain account. This can be exploited to authenticate to the Active
  Directory domain using a revoked certificate.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-086.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms1-086.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

# Active Directory
if((hotfix_missing(name:"2601626") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS\Performance"))
{
  ntdsaVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Ntdsa.dll");
  if(ntdsaVer != NULL)
  {
    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.4910")){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
          exit(0);
      }
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

# Active Directory Application Mode
if((hotfix_missing(name:"2616310") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\ADAM\Linkage"))
{
  adamdsaVer = fetch_file_version(sysPath:sysPath, file_name:"ADAM\Adamdsa.dll");
  if(adamdsaVer != NULL)
  {
    if(hotfix_check_sp(xp:4, win2003:3) > 0)
    {
      XPSP = get_kb_item("SMB/WinXP/ServicePack");
      k3SP = get_kb_item("SMB/Win2003/ServicePack");
      if(("Service Pack 3" >< XPSP) || ("Service Pack 2" >< k3SP))
      {
        if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4905")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

if((hotfix_missing(name:"2601626") == 0)){
  exit(0);
}

## AD LAS For Windows 7, vista and 2008 server
dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Ntdsai.dll");
if(!dllVer){
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18507")||
       version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22704")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16871") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.21000", test_version2:"6.1.7600.21034") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17675") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21801")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
