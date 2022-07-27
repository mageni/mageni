###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Authentication Verification Remote Code Execution Vulnerability (981210)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-19
#       - To detect required file version on vista, win 2008 and win 7
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
  script_oid("1.3.6.1.4.1.25623.1.0.900237");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_bugtraq_id(39328, 39332);
  script_cve_id("CVE-2010-0486", "CVE-2010-0487");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Authentication Verification Remote Code Execution Vulnerability (981210)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39371");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-019.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could lead to complete system being compromised.");
  script_tag(name:"insight", value:"An error exists in the Windows Authenticode Signature Verification function
  used for portable executable (PE) and cabinet(.cab) file formats.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-019.");
  script_tag(name:"affected", value:"Authenticode Signature Verification 5.1 on,
  Microsoft Windows 2K  Service Pack 4 and prior.
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.

  Authenticode Signature Verification 6.0 on,
  Microsoft Windows vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.

  Authenticode Signature Verification 6.1 on,
  Windows 7

  Cabinet File Viewer Shell Extension 5.1 on,
  Microsoft Windows 2K  Service Pack 4 and prior.

  Cabinet File Viewer Shell Extension 6.0 on,
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.
  Cabinet File Viewer Shell Extension 6.1 on, Windows 7");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## MS10-019 Hotfix check
if(hotfix_missing(name:"978601") == 0 && hotfix_missing(name:"979309") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  authSigVer = fetch_file_version(sysPath:sysPath, file_name:"Wintrust.dll");
  if(!authSigVer){
    exit(0);
  }
}

if(authSigVer)
{
  if(hotfix_check_sp(win2k:5) > 0)
  {
    if(version_in_range(version:authSigVer, test_version:"5.1",
                        test_version2:"5.131.2195.7374")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  else if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_in_range(version:authSigVer, test_version:"5.1",
                          test_version2:"5.131.2600.3660")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      if(version_in_range(version:authSigVer, test_version:"5.1",
                          test_version2:"5.131.2600.5921")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }

  else if(hotfix_check_sp(win2003:3) > 0)
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_in_range(version:authSigVer, test_version:"5.1",
                          test_version2:"5.131.3790.4641")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  cabBViewVer = fetch_file_version(sysPath:sysPath, file_name:"Cabview.dll");
  if(!cabBViewVer){
    exit(0);
  }
}

if(cabBViewVer)
{
  if(hotfix_check_sp(win2k:5) > 0)
  {
    if(version_in_range(version:cabBViewVer, test_version:"5.0",
                        test_version2:"5.0.3900.7368")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_in_range(version:cabBViewVer, test_version:"6.0",
                          test_version2:"6.0.2900.3662")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
    else if("Service Pack 3" >< SP)
    {
      if(version_in_range(version:cabBViewVer, test_version:"6.0",
                          test_version2:"6.0.2900.5926")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
  }

  else if(hotfix_check_sp(win2003:3) > 0)
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_in_range(version:cabBViewVer, test_version:"6.0",
                          test_version2:"6.0.3790.4648")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
  }
}

sysPath = smb_get_system32root();
if(sysPath)
{
  cabVer = fetch_file_version(sysPath:sysPath, file_name:"Cabview.dll");
  if(!cabVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:cabVer, test_version:"6.0.6001.18404")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:cabVer, test_version:"6.0.6002.18184")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:cabVer, test_version:"6.0.6001.18404")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:cabVer, test_version:"6.0.6002.18184")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
 security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:cabVer, test_version:"6.1.7600.16500")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
