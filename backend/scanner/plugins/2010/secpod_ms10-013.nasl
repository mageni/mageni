###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft DirectShow Remote Code Execution Vulnerability (977935)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-18
# - To detect file version 'Quartz.dll' on vista, win 2008 and win 7
# - Updated to support GDR and LDR versions on 2012-04-23
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
  script_oid("1.3.6.1.4.1.25623.1.0.902117");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0250");
  script_bugtraq_id(38112);
  script_name("Microsoft DirectShow Remote Code Execution Vulnerability (977935)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0346");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-013.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page.");
  script_tag(name:"affected", value:"Microsoft Windows 7
  Microsoft Windows 2000 Service Pack 4 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior
  Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by a heap overflow error in the Microsoft DirectShow
  component when handling malformed AVI files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-013.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

sysVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\Avifil32.dll");
sysVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Quartz.dll");
if(!sysVer1 && !sysVer2){
   exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if((sysVer1 && version_is_less(version:sysVer1, test_version:"5.0.2195.7359")) ||
     (sysVer2 && (version_in_range(version:sysVer2, test_version:"6.5", test_version2:"6.5.1.912") ||
     version_in_range(version:sysVer2, test_version:"6.1", test_version2:"6.1.9.737")))) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if((sysVer1 && version_is_less(version:sysVer1, test_version:"5.1.2600.3649")) ||
       (sysVer2 && version_is_less(version:sysVer2, test_version:"6.5.2600.3649"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if((sysVer1 && version_is_less(version:sysVer1, test_version:"5.1.2600.5908")) ||
       (sysVer2 && version_is_less(version:sysVer2, test_version:"6.5.2600.5908"))){
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
    if((sysVer1 && version_is_less(version:sysVer1, test_version:"5.2.3790.4625")) ||
       (sysVer2 && version_is_less(version:sysVer2, test_version:"6.5.3790.4625"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0 && sysVer2)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:sysVer2, test_version:"6.6.6001.18389") ||
       version_in_range(version:sysVer2, test_version:"6.6.6001.22000", test_version2:"6.6.6001.22589")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer2, test_version:"6.6.6002.18158") ||
       version_in_range(version:sysVer2, test_version:"6.6.6002.22000", test_version2:"6.6.6002.22294")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0 && sysVer2)
{
  if(version_is_less(version:sysVer2, test_version:"6.6.7600.16490")||
     version_in_range(version:sysVer2, test_version:"6.6.7600.20000", test_version2:"6.6.7600.20599")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
