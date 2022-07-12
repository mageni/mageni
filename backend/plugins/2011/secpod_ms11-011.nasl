###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Kernel Elevation of Privilege Vulnerability (2393802)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902337");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2010-4398", "CVE-2011-0045");
  script_bugtraq_id(45045, 46136);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Kernel Elevation of Privilege Vulnerability (2393802)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42356");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0324");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/cve/CVE-2011-0045");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-011.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers or malicious users to
  execute arbitrary code with kernel privileges.");
  script_tag(name:"affected", value:"Microsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.");
  script_tag(name:"insight", value:"The flaws are due to

  - an integer truncation error in the Windows kernel that does not properly
    validate user-supplied data before allocating memory.

  - a buffer overflow error in the 'win32k.sys' driver when interacting with
    the Windows kernel.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-011.");
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

## MS11-011 Hotfix
if((hotfix_missing(name:"2393802") == 0)){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Ntoskrnl.exe");
  if(dllVer)
  {
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
    	if(version_is_less(version:dllVer, test_version:"5.1.2600.6055")){
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
        if(version_is_less(version:dllVer, test_version:"5.2.3790.4789")){
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
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Ntoskrnl.exe");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:3, win2008:3) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP) {
        SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18537")||
           version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22776")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18326")||
           version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22504")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win7:2) > 0)
    {
      if(version_in_range(version:dllVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16694")||
         version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20825")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
