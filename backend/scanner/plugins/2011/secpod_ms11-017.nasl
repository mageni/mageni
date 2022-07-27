###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Remote Desktop Client Remote Code Execution Vulnerability (2508062)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900273");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-03-09 15:35:07 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-0029");
  script_bugtraq_id(46678);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Remote Desktop Client Remote Code Execution Vulnerability (2508062)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43628");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-017.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow authenticated attackers to execute
  arbitrary code with elevated privileges.");
  script_tag(name:"insight", value:"The flaw is caused by the way Windows Remote Desktop Client handles loading
  of DLL files. Remote attacker can execute arbitrary code by tricking a user
  to open a legitimate Remote Desktop configuration file (.rdp) that
  is located in the same network directory as a specially crafted dynamic
  link library (DLL) file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS11-017.");
  script_tag(name:"affected", value:"Remote Desktop Connection 5.2 Client

  - Windows XP Service Pack 3 and prior

  Remote Desktop Connection 6.0/6.1 Client

  - Windows XP Service Pack 3

  - Windows Vista Service Pack 2 and prior

  - Windows Server 2003 Service Pack 2 and prior

  - Windows Server 2008 Service Pack 2 and prior

  Remote Desktop Connection 7.0 Client

  - Windows 7

  - Windows XP Service Pack 3 and prior

  - Windows Vista Service Pack 2 and prior");
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

if((hotfix_missing(name:"2483618") == 0)||(hotfix_missing(name:"2481109") == 0)||
   (hotfix_missing(name:"2483619") == 0)||(hotfix_missing(name:"2483614") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Mstscax.dll");
if(!dllVer){
  if(hotfix_check_sp(xp:4) > 0){
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\2k3mstscax.dll");
  } else{
    exit(0);
  }

  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {

    ## 2k3mstscax.dll 5.2.3790.4807 SP3GDR and SP3QFE for 5.2 version
    ## MSTSCAX.dll 6.0.6001.18589 SP3GDR and 6.0.6001.22840 SP3QFE for 6.0 version
    ## MSTSCAX.dll 6.1.7600.16722 SP3GDR and 6.1.7600.20861 SP3QFE for 7.0 version
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4807")||
       version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18588")||
       version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22839")||
       version_in_range(version:dllVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16721")||
       version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20860")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## MSTSCAX.dll 6.0.6001.18564 SP3GDR and 6.0.6001.22815 SP3QFE for 6.1 version
    ## Ignoring (MUI) for RDP, as the file path is having KB number and some random character
    if( version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18563")||
        version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22814")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if(!SP){
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }
  if("Service Pack 1" >< SP)
  {
    ## MSTSCAX.dll 6.0.6001.18564 SP1GDR and 6.0.6001.22815 SP1QFE for 6.0 version
    ## MSTSCAX.dll 6.1.7600.16722 SP1GDR and 6.1.7600.20861 SP1QFE for 7.0 version
    if( version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18563")||
        version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22814")||
        version_in_range(version:dllVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16721")||
        version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20860")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## MSTSCAX.dll 6.0.6002.18356 SP2GDR and 6.0.6002.22550 SP2QFE for 6.1 version
    ## MSTSCAX.dll 6.1.7600.16722 SP1GDR and 6.1.7600.20861 SP1QFE for 7.0 version
    if( version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18355")||
        version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22549")||
        version_in_range(version:dllVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16721")||
        version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20860")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:2) > 0)
{
  ## MSTSCAX.dll 6.1.7600.16722 SP1GDR and 6.1.7600.20861 SP1QFE for 7.0 version
  if(version_in_range(version:dllVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16721")||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20860")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
